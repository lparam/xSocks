#include <string.h>
#include "sodium.h"


/*
 *
 * Cipher Text
 * +------+-----+----------+
 * |NONCE | TAG |  DATA    |
 * +------+-----+----------+
 * |  8   | 16  | Variable |
 * +------+-----+----------+
 *
 */

#define COB crypto_onetimeauth_BYTES // 16U
#define COKB crypto_onetimeauth_KEYBYTES // 32U
#define CSSNB crypto_stream_salsa20_NONCEBYTES // 8U
#define CSSKB crypto_stream_salsa20_KEYBYTES //32U

static uint8_t secret_key[crypto_generichash_BYTES];


static int
salsa208poly1305_encrypt(uint8_t *c, const uint8_t *m, const uint32_t mlen,
  const uint8_t *n, const uint8_t *k) {
    uint8_t cok[COKB];

    crypto_stream_salsa208(cok, COKB, n, k);
    crypto_stream_salsa208_xor(c + COB, m, mlen, n, k);
    crypto_onetimeauth_poly1305(c, c + COB, mlen, cok);

    return 0;
}

static int
salsa208poly1305_decrypt(uint8_t *m, const uint8_t *c, const uint32_t clen,
  const uint8_t *n, const uint8_t *k) {
    uint8_t cok[COKB];

    if (clen < COB) {
        return -1;
    }

    int mlen = clen - COB;

    crypto_stream_salsa208(cok, COKB, n, k);
    if (crypto_onetimeauth_poly1305_verify(c, c + COB, mlen, cok) == 0) {
        return crypto_stream_salsa208_xor(m, c + COB, mlen, n, k);
    }

    return -1;
}

int
crypto_init(const char *password) {
    if (sodium_init() == -1) {
        return 1;
    }

    randombytes_set_implementation(&randombytes_salsa20_implementation);
    randombytes_stir();

    return crypto_generichash(secret_key, sizeof secret_key, (uint8_t*)password, strlen(password), NULL, 0);
}

int
crypto_generickey(uint8_t *out, size_t outlen, uint8_t *in, size_t inlen, uint8_t *key, size_t keylen) {
    return crypto_generichash(out, outlen, in, inlen, key, keylen);
}

int
crypto_encrypt(uint8_t *c, const uint8_t *m, const uint32_t mlen) {
    uint8_t nonce[CSSNB];
    randombytes_buf(nonce, CSSNB);
    memcpy(c, nonce, CSSNB);
    return salsa208poly1305_encrypt(c + CSSNB, m, mlen, nonce, secret_key);
}

int
crypto_decrypt(uint8_t *m, const uint8_t *c, const uint32_t clen) {
    uint8_t nonce[CSSNB];
    memcpy(nonce, c, CSSNB);
    return salsa208poly1305_decrypt(m, c + CSSNB, clen - CSSNB, nonce, secret_key);
}
