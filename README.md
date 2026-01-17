# OASP — Open Audio Streaming Protocol

OASP (Open Audio Streaming Protocol) is a protocol and reference implementation for bidirectional low-latency audio streaming over Bluetooth L2CAP. It uses Opus for audio compression, a small framing header for transport integrity, and is designed as a reference for building audio sink/source implementations (e.g., hands‑free, intercoms, low-latency audio links).

This repository contains:
- A Rust-based BlueZ-profile L2CAP server: [oasp_bt/src/main.rs](https://github.com/commandline-studios/OASP/blob/b2bcec9121734bc5b133cacd970977fc35659271/oasp_bt/src/main.rs)
- A minimal C client: [oasp_client/oasp.c](https://github.com/commandline-studios/OASP/blob/b2bcec9121734bc5b133cacd970977fc35659271/oasp_client/oasp.c)

Status: experimental / proof-of-concept. Use for learning, testing, or as a starting point for more feature-rich products.

---

## Design & Specification

### Goals
- Low-latency bidirectional audio streaming over Bluetooth L2CAP.
- Simple, small packet framing for easy interoperability.
- Reference implementations in Rust (server) and C (client).
- Uses Opus as the audio codec for high quality at low bitrates.

### Transport
- Underlying transport: Bluetooth L2CAP (SOCK_SEQPACKET on Linux / BlueZ).
- Service UUID (profile registration): `11111111-2222-3333-4444-555555555555`.
- L2CAP PSM: 0x1001 (hex). Both server and client use this PSM by default.

### Audio Format
- Codec: Opus
- Sampling rate: 48 000 Hz
- Channels: Stereo (2)
- PCM format (when using ALSA): signed 16-bit, interleaved
- Default Opus frame size: 960 samples per channel (20 ms at 48 kHz)
- Maximum compressed frame buffer: 4000 bytes (implementation buffer size)

### Packet framing
Each packet sent over the L2CAP link has a small header followed by the Opus payload:

- Bytes 0–1: frame length (big-endian, unsigned 16-bit) — length of the compressed Opus payload in bytes
- Byte 2: checksum (simple additive checksum: sum of payload bytes modulo 256)
- Bytes 3..: compressed Opus frame payload

Notes:
- The small additive checksum is a lightweight integrity check for a single frame. It is not cryptographically secure.
- The receiver reads the 3-byte header first, then reads exactly `frame length` bytes. If the checksum fails, the frame is dropped.

---

## Latency

- Opus frame duration: FRAME_SIZE / SAMPLE_RATE
  - Default in the examples: 960 samples / 48 000 Hz = 0.02 s = 20 ms per frame
- Encoding time: small, often 1–5 ms depending on CPU and Opus complexity
- Network transmission (L2CAP/Bluetooth air time): typically 1–10 ms for a single packet, depending on radio conditions
- Jitter buffering and ALSA buffering: configurable; can add 0–100+ ms depending on settings
- Decoding time: small, often 1–5 ms

Typical measured one-way latencies you can expect with the default configuration (20 ms frames, small buffers) are roughly 20–80 ms one-way in good conditions. End‑to‑end round-trip for interactive use (capture → encode → transmit → decode → playback → capture again) will be higher (40–160 ms).

---

## Reliability & Error Handling

- Simple checksum: used to detect obvious corruption. Corrupted frames are dropped.
- There is no retransmission at the protocol layer — this is intentional to keep latency low.

---

## Troubleshooting

- "Failed to bind L2CAP socket" — likely insufficient privileges or another service is already bound to the chosen PSM. Try running as root or using another PSM.
- ALSA xruns or audio underruns — increase ALSA buffer sizes or use real-time priorities for audio threads.
- DBus or BlueZ profile registration errors — ensure your process has access to the system D-Bus and BlueZ is running.
- Check logs and use simple tools like `hcitool`, `btmgmt`, or `bluetoothctl` to inspect Bluetooth adapter state.

---

## Contributing

Contributions, bug reports, and improvements are welcome. If you add protocol changes that affect interoperability, document them clearly.

---

## License

This project is provided with a custom [LICENSE](https://github.com/commandline-studios/OASP/blob/main/LICENSE)

---

## Installation & Build (Quick Start)

The following instructions target Debian/Ubuntu systems. Arch based systems not supported.

Prerequisites
- Rust toolchain (for the server)
- GCC (for the C client)
- Development libraries: ALSA, libdbus-1, libopus, libbluetooth
- BlueZ running on the system

Install commands (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install -y build-essential git curl \
  libasound2-dev libdbus-1-dev libopus-dev libbluetooth-dev pkg-config
```

Install Rust (if not present):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Build server (Rust)
```bash
cd oasp_bt
cargo build --release

sudo ./target/release/oasp_bt
```

Build client (C)
```bash
cd oasp_client
gcc -o oasp oasp.c -lopus -lbluetooth
sudo ./oasp
```
### Please take note that the C client should be ran from the microcontroller and not on the host. Replace the commented out stubs in [oasp_client/oasp.c](https://github.com/commandline-studios/OASP/blob/b2bcec9121734bc5b133cacd970977fc35659271/oasp_client/oasp.c) with the platform specific code.
---
