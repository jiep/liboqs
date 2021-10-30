#ifndef PQCLEAN_NTRUHRSS701_AVX2_API_H
#define PQCLEAN_NTRUHRSS701_AVX2_API_H

#include <stdint.h>

#define PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_SECRETKEYBYTES 1450
#define PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_PUBLICKEYBYTES 1138
#define PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_CIPHERTEXTBYTES 1138
#define PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_BYTES 32

#define PQCLEAN_NTRUHRSS701_AVX2_CRYPTO_ALGNAME "ntruhrss701"

int PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_enc(uint8_t *c, uint8_t *k, const uint8_t *pk, const uint8_t *coins);

int PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_dec(uint8_t *k, const uint8_t *c, const uint8_t *sk);

#endif
