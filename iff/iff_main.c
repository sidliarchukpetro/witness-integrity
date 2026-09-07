/*
 * iff_main.c — відповідач «свій-чужий» на ESP32-S3 з ATECC608B.
 *
 * Приймає з UART (консоль) 64 hex-символи — 32-байтовий виклик.
 * Підписує його ключем слота 0, який живе в кремнії й не покидає чип.
 * Віддає серійник, публічний ключ і підпис.
 *
 * Ініціалізація, low-s нормалізація і константи P-256 узяті дослівно з
 * робочого iv_net.c, який відпрацював на цьому чипі. Не з пам'яті.
 *
 * Приймальна сторона (Pi, iff.py) перевіряє підпис за реєстром.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cryptoauthlib.h"

static const char *TAG = "iv_iff";

/* ---- узято з iv_net.c дослівно ---------------------------------- */

static const uint8_t P256_N[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,
    0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51
};
static const uint8_t P256_N_HALF[32] = {
    0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,
    0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,
    0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8
};
static int be_cmp(const uint8_t *a, const uint8_t *b, int n) {
    for (int i = 0; i < n; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static void be_sub(uint8_t *out, const uint8_t *a, const uint8_t *b, int n) {
    int borrow = 0;
    for (int i = n - 1; i >= 0; i--) {
        int d = (int)a[i] - (int)b[i] - borrow;
        borrow = d < 0; out[i] = (uint8_t)(d & 0xFF);
    }
}

/* ---- hex ---------------------------------------------------------- */

static void hex_n(char *dst, const uint8_t *src, int n) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        dst[2*i]   = H[src[i] >> 4];
        dst[2*i+1] = H[src[i] & 0xF];
    }
    dst[2*n] = '\0';
}

static int hex2bin(const char *hex, uint8_t *out, int n) {
    for (int i = 0; i < n; i++) {
        int hi = -1, lo = -1;
        char a = hex[2*i], b = hex[2*i + 1];
        if (a >= '0' && a <= '9') hi = a - '0';
        else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        if (b >= '0' && b <= '9') lo = b - '0';
        else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* ---- підпис виклику ---------------------------------------------- */

/* Той самий шлях, що й у iv_net.c: atcab_sign(slot 0) + low-s. */
static int sign_challenge(const uint8_t ch[32], char sig_hex[129]) {
    uint8_t sig[64];
    if (atcab_sign(0, ch, sig) != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_sign failed");
        return -1;
    }
    if (be_cmp(&sig[32], P256_N_HALF, 32) > 0) {
        uint8_t s2[32];
        be_sub(s2, P256_N, &sig[32], 32);
        memcpy(&sig[32], s2, 32);
    }
    hex_n(sig_hex, sig, 64);
    return 0;
}

/* ---- читання рядка з консолі -------------------------------------- */

static int read_line(char *buf, int max) {
    int n = 0;
    while (n < max - 1) {
        int c = getchar();
        if (c == EOF) { vTaskDelay(pdMS_TO_TICKS(20)); continue; }
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[n++] = (char)c;
    }
    buf[n] = '\0';
    return n;
}

/* ---- головний цикл ------------------------------------------------ */

void app_main(void) {
    uint8_t serial[9];
    uint8_t pub[64];
    char pub_hex[129], ser_hex[19], sig_hex[129];

    vTaskDelay(pdMS_TO_TICKS(500));

    if (atcab_init(&cfg_ateccx08a_i2c_default) != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_init failed");
        vTaskDelay(pdMS_TO_TICKS(10000));
        esp_restart();
        return;
    }
    if (atcab_read_serial_number(serial) != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "serial read failed");
        return;
    }
    if (atcab_get_pubkey(0, pub) != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "pubkey read failed");
        return;
    }
    hex_n(ser_hex, serial, 9);
    hex_n(pub_hex, pub, 64);

    printf("\n=== IFF RESPONDER ===\n");
    printf("SERIAL %s\n", ser_hex);
    printf("PUBKEY %s\n", pub_hex);
    printf("READY  надішли 64 hex-символи виклику й Enter\n\n");

    char line[160];
    uint8_t ch[32];

    for (;;) {
        int n = read_line(line, sizeof(line));
        if (n == 0) continue;

        if (strcmp(line, "id") == 0) {
            printf("SERIAL %s\nPUBKEY %s\n", ser_hex, pub_hex);
            continue;
        }
        if (n != 64) {
            printf("ERR виклик має бути 64 hex-символи, отримано %d\n", n);
            continue;
        }
        if (hex2bin(line, ch, 32) != 0) {
            printf("ERR не hex\n");
            continue;
        }

        int64_t t0 = esp_timer_get_time();
        if (sign_challenge(ch, sig_hex) != 0) {
            printf("ERR підпис не вдався\n");
            continue;
        }
        int64_t dt = (esp_timer_get_time() - t0) / 1000;

        printf("SERIAL %s\n", ser_hex);
        printf("PUBKEY %s\n", pub_hex);
        printf("SIG    %s\n", sig_hex);
        printf("MS     %lld\n\n", dt);
    }
}
