use dbus::arg::{PropMap, Variant};
use dbus::blocking::Connection;
use std::collections::HashMap;
use std::convert::TryInto;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ALSA
use alsa::pcm::{Access, Format, HwParams, PCM};
use alsa::{Direction, ValueOr};

// Opus
use opus::{Application, Channels, Decoder, Encoder};

// Libc
use libc::{accept, bind, c_uchar, c_ushort, fcntl, listen, read, socket, write, AF_BLUETOOTH, O_NONBLOCK, SOCK_SEQPACKET, sockaddr};
use dbus::Path;

use ctrlc;

const OASP_UUID: &str = "11111111-2222-3333-4444-555555555555";
const SAMPLE_RATE: u32 = 48000;
const CHANNELS: Channels = Channels::Stereo; // small QoL
const FRAME_SIZE: usize = 960;
const COMPRESSED_SIZE: usize = 4000;
const L2CAP_PSM: u16 = 0x1001;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrL2 {
    l2_family: c_ushort,
    l2_psm: c_ushort,
    l2_bdaddr: [c_uchar; 6],
    l2_cid: c_ushort,
    l2_bdaddr_type: c_uchar,
}

fn htobs(x: u16) -> u16 { x.to_le() }

// ============================ BlueZ OASP Profile ============================
fn register_oasp_profile() -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::new_system()?;
    let proxy = conn.with_proxy("org.bluez", "/org/bluez", Duration::from_secs(5));

    let mut options: PropMap = HashMap::new();
    options.insert("AutoConnect".into(), Variant(Box::new(true)));
    options.insert("Role".into(), Variant(Box::new("server".to_string())));
    options.insert("RequireAuthentication".into(), Variant(Box::new(false)));
    options.insert("RequireAuthorization".into(), Variant(Box::new(false)));

    proxy.method_call::<(), _, _, _>(
        "org.bluez.ProfileManager1",
        "RegisterProfile",
        (Path::new("/org/bluez/oasp_profile")?, OASP_UUID, options),
    )?;

    println!("[OASP] ✅ Profile registered with BlueZ");
    Ok(())
}

// ============================ L2CAP Server ============================
fn setup_l2cap_server() -> RawFd {
    unsafe {
        let sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, 0);
        if sock < 0 { panic!("[OASP] ❌ Failed to create L2CAP socket"); }

        fcntl(sock, libc::F_SETFL, O_NONBLOCK);

        let mut addr: SockAddrL2 = std::mem::zeroed();
        addr.l2_family = AF_BLUETOOTH as u16;
        addr.l2_psm = htobs(L2CAP_PSM);

        if bind(sock, &addr as *const _ as *const sockaddr, std::mem::size_of::<SockAddrL2>() as u32) < 0 {
            panic!("[OASP] ❌ Failed to bind L2CAP socket");
        }

        if listen(sock, 5) < 0 { panic!("[OASP] ❌ Failed to listen on L2CAP socket"); }

        println!("[OASP] 📡 L2CAP server listening on PSM 0x{:X}", L2CAP_PSM);
        sock
    }
}

// ============================ ALSA PCM setup ============================
fn setup_pcm(direction: Direction) -> PCM {
    let pcm = PCM::new("default", direction, false).expect("Failed to open PCM device");
    {
        let hw = HwParams::any(&pcm).expect("Failed to get hw params");
        hw.set_channels(CHANNELS as u32).unwrap();
        hw.set_rate(SAMPLE_RATE, ValueOr::Nearest).unwrap();
        hw.set_format(Format::s16()).unwrap();
        hw.set_access(Access::RWInterleaved).unwrap();
        pcm.hw_params(&hw).unwrap();
        hw.set_buffer_size_near(FRAME_SIZE.try_into().unwrap()).unwrap();
    }
    pcm
}

// ============================ Safe read/write ============================
fn safe_write(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe { write(fd, buf[total..].as_ptr() as *const _, buf.len() - total) };
        if n <= 0 { return Err(std::io::Error::last_os_error()); }
        total += n as usize;
    }
    Ok(total)
}

fn safe_read(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    if n < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(n as usize)
}

// ============================ Per-client handler ============================
fn handle_client(fd: RawFd, running: Arc<AtomicBool>) {
    println!("[OASP] 🎧 Client connected!");

    let pcm_in = setup_pcm(Direction::Capture);
    let pcm_out = setup_pcm(Direction::Playback);

    let mut enc = Encoder::new(SAMPLE_RATE, CHANNELS, Application::Audio).unwrap();
    let mut dec = Decoder::new(SAMPLE_RATE, CHANNELS).unwrap();

    let mut buffer_in = vec![0i16; FRAME_SIZE * CHANNELS as usize];
    let mut buffer_out = vec![0i16; FRAME_SIZE * CHANNELS as usize];
    let mut compressed = vec![0u8; COMPRESSED_SIZE];
    let mut recv_buf = vec![0u8; COMPRESSED_SIZE + 4]; // extra bytes for checksum/seq

    let send_fd = fd;
    let recv_fd = fd;

    // Ring buffers for jitter
    let tx_buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let rx_buffer = Arc::new(Mutex::new(Vec::<u8>::new()));


    // Sender thread: mic → client
    let running_send = running.clone();
    let tx_buf_send = tx_buffer.clone();
    let sender = thread::spawn(move || {
        while running_send.load(Ordering::SeqCst) {
            let io_in = pcm_in.io_i16().unwrap();
            let read_count = io_in.readi(&mut buffer_in).unwrap_or(0);
            if read_count > 0 {
                let len = enc.encode(&buffer_in[..read_count], &mut compressed).unwrap();
                let checksum: u8 = compressed[..len].iter().fold(0, |acc, &b| acc.wrapping_add(b));
                let mut packet = vec![(len >> 8) as u8, len as u8, checksum];
                packet.extend_from_slice(&compressed[..len]);

                // Echo mitigation: only send if running
                if safe_write(send_fd, &packet).is_err() { break; }

                let mut buf = tx_buf_send.lock().unwrap();
                buf.extend_from_slice(&packet);
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    // Receiver thread: client → speaker
    let running_recv = running.clone();
    let rx_buf_recv = rx_buffer.clone();
    let receiver = thread::spawn(move || {
        while running_recv.load(Ordering::SeqCst) {
            match safe_read(recv_fd, &mut recv_buf) {
                Ok(0) => break,
                Ok(r) => {
                    if r > 3 {
                        let frame_len = ((recv_buf[0] as usize) << 8) | (recv_buf[1] as usize);
                        let checksum = recv_buf[2];
                        if frame_len > 0 && frame_len <= COMPRESSED_SIZE {
                            let frame_data = &recv_buf[3..3+frame_len];
                            let calc_sum: u8 = frame_data.iter().fold(0, |acc, &b| acc.wrapping_add(b));
                            if calc_sum == checksum {
                                dec.decode(frame_data, &mut buffer_out, false).unwrap_or(0);
                                let io_out = pcm_out.io_i16().unwrap();
                                let _ : std::result::Result<usize, alsa::Error> = io_out.writei(&buffer_out).or_else(|_| {
                                    pcm_out.prepare().ok();
                                    Ok(0)
                                });
                            }
                        }
                    }
                }
                Err(_) => break,
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    sender.join().ok();
    receiver.join().ok();
    println!("[OASP] Client disconnected");
    unsafe { libc::close(fd); }
}

// ============================ Main ============================
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n[OASP] Shutting down server...");
        r.store(false, Ordering::SeqCst);
    })?;

    register_oasp_profile()?;
    let server_fd = setup_l2cap_server();

    while running.load(Ordering::SeqCst) {
        let client_fd = unsafe { accept(server_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd >= 0 {
            println!("[OASP] Spawning thread for new client");
            let r_clone = running.clone();
            thread::spawn(move || handle_client(client_fd, r_clone));
        } else {
            thread::sleep(Duration::from_millis(50));
        }
    }

    println!("[OASP] Server shutdown complete");
    Ok(())
}
