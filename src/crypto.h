#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

int crypto_init(const char *password);
int crypto_generickey(uint8_t *out, size_t outlen, uint8_t *in, size_t inlen, uint8_t *key, size_t keylen);
int crypto_encrypt(uint8_t *c, const uint8_t *m, const uint32_t mlen);
int crypto_decrypt(uint8_t *m, const uint8_t *c, const uint32_t clen);

#endif
