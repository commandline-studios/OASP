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

static int l2cap_fd = -1;

int platform_capture_audio(int16_t *buffer, int size);   // Implement on MCU
void platform_play_audio(int16_t *buffer, int size);    // Implement on MCU

static int oasp_send_frame(const uint8_t *data, int len) {
    if (!data || len <= 0 || l2cap_fd < 0) return -1;
    uint8_t pkt[COMPRESSED_SIZE + 2];
    if (len > COMPRESSED_SIZE) len = COMPRESSED_SIZE;
    pkt[0] = (len >> 8) & 0xFF;
    pkt[1] = len & 0xFF;
    memcpy(pkt + 2, data, len);
    int sent = 0;
    while (sent < len + 2) {
        int n = write(l2cap_fd, pkt + sent, len + 2 - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return sent;
}

static int oasp_receive_frame(uint8_t *buf, int max_len) {
    if (!buf || max_len <= 2 || l2cap_fd < 0) return -1;
    int r = 0;
    while (r < 2) {
        int n = read(l2cap_fd, buf + r, 2 - r);
        if (n <= 0) return -1;
        r += n;
    }
    int frame_len = (buf[0] << 8) | buf[1];
    if (frame_len <= 0 || frame_len > max_len - 2) return -1;
    int received = 0;
    while (received < frame_len) {
        int n = read(l2cap_fd, buf + 2 + received, frame_len - received);
        if (n <= 0) return -1;
        received += n;
    }
    return frame_len;
}

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

void oasp_loop() {
    uint8_t compressed_tx[COMPRESSED_SIZE];
    uint8_t compressed_rx[COMPRESSED_SIZE];
    int16_t pcm_in[FRAME_SIZE], pcm_out[FRAME_SIZE];
    int err;
    OpusEncoder *enc = opus_encoder_create(48000, 1, OPUS_APPLICATION_AUDIO, &err);
    OpusDecoder *dec = opus_decoder_create(48000, 1, &err);
    if (!enc || !dec) return;
    while (1) {
        platform_capture_audio(pcm_in, FRAME_SIZE);
        int len = opus_encode(enc, pcm_in, FRAME_SIZE, compressed_tx, COMPRESSED_SIZE);
        if (len > 0) oasp_send_frame(compressed_tx, len);
        int r = oasp_receive_frame(compressed_rx, COMPRESSED_SIZE);
        if (r > 0) {
            int decoded = opus_decode(dec, compressed_rx + 2, r, pcm_out, FRAME_SIZE, 0);
            if (decoded > 0) platform_play_audio(pcm_out, decoded);
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
