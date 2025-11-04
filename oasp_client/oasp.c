#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "opus/opus.h"

#define FRAME_SIZE 960
#define COMPRESSED_SIZE 4000
#define L2CAP_PSM 0x1001
#define CHANNELS 2  // stereo

static int l2cap_fd = -1;

// Dummy capture/playback functions commented out for now
//int platform_capture_audio(int16_t *buffer, int size);
//void platform_play_audio(int16_t *buffer, int size);

// ============================ OASP send/recv ============================
static int oasp_send_frame(const uint8_t *data, int len) {
    if (!data || len <= 0 || l2cap_fd < 0) return -1;
    uint8_t pkt[COMPRESSED_SIZE + 3]; // 2 bytes len + 1 checksum
    if (len > COMPRESSED_SIZE) len = COMPRESSED_SIZE;

    pkt[0] = (len >> 8) & 0xFF;
    pkt[1] = len & 0xFF;

    uint8_t checksum = 0;
    for (int i = 0; i < len; i++) checksum += data[i];
    pkt[2] = checksum;

    memcpy(pkt + 3, data, len);

    int sent = 0;
    while (sent < len + 3) {
        int n = write(l2cap_fd, pkt + sent, len + 3 - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int oasp_receive_frame(uint8_t *buf, int max_len) {
    if (!buf || max_len <= 3 || l2cap_fd < 0) return -1;

    int r = 0;
    while (r < 3) {
        int n = read(l2cap_fd, buf + r, 3 - r);
        if (n <= 0) return -1;
        r += n;
    }

    int frame_len = (buf[0] << 8) | buf[1];
    uint8_t checksum = buf[2];

    if (frame_len <= 0 || frame_len > max_len - 3) return -1;

    int received = 0;
    while (received < frame_len) {
        int n = read(l2cap_fd, buf + 3 + received, frame_len - received);
        if (n <= 0) return -1;
        received += n;
    }

    uint8_t calc_sum = 0;
    for (int i = 0; i < frame_len; i++) calc_sum += buf[3 + i];

    if (calc_sum != checksum) return -1; // drop corrupted frame

    return frame_len;
}

// ============================ L2CAP connect ============================
int platform_l2cap_connect(const char *bt_addr) {
    if (!bt_addr) return -1;
    struct sockaddr_l2 addr;
    int s = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (s < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    str2ba(bt_addr, &addr.l2_bdaddr);
    addr.l2_psm = htobs(L2CAP_PSM);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }
    l2cap_fd = s;
    return s;
}

// ============================ OASP loop ============================
void oasp_loop() {
    uint8_t compressed_tx[COMPRESSED_SIZE];
    uint8_t compressed_rx[COMPRESSED_SIZE];
    int16_t pcm_in[FRAME_SIZE * CHANNELS], pcm_out[FRAME_SIZE * CHANNELS];
    int err;

    OpusEncoder *enc = opus_encoder_create(48000, CHANNELS, OPUS_APPLICATION_AUDIO, &err);
    OpusDecoder *dec = opus_decoder_create(48000, CHANNELS, &err);
    if (!enc || !dec) return;

    while (1) {
        // ===== Capture mic =====
        // platform_capture_audio(pcm_in, FRAME_SIZE * CHANNELS);
        // int len = opus_encode(enc, pcm_in, FRAME_SIZE, compressed_tx, COMPRESSED_SIZE);
        int len = 0; // dummy for now
        if (len > 0) {
            oasp_send_frame(compressed_tx, len);
        }

        // ===== Receive server audio =====
        int r = oasp_receive_frame(compressed_rx, COMPRESSED_SIZE);
        if (r > 0) {
            int decoded = opus_decode(dec, compressed_rx, r, pcm_out, FRAME_SIZE, 0);
            if (decoded > 0) {
                // platform_play_audio(pcm_out, decoded * CHANNELS);
            }
        }
    }

    opus_encoder_destroy(enc);
    opus_decoder_destroy(dec);
}

int main() {
    if (platform_l2cap_connect("00:11:22:33:44:55") < 0) return 1;
    oasp_loop();
    close(l2cap_fd);
    return 0;
}
