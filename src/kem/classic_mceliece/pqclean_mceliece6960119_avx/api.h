#ifndef PQCLEAN_MCELIECE6960119_AVX_API_H
#define PQCLEAN_MCELIECE6960119_AVX_API_H

#include <stdint.h>

#define PQCLEAN_MCELIECE6960119_AVX_CRYPTO_ALGNAME "Classic McEliece 6960119"
#define PQCLEAN_MCELIECE6960119_AVX_CRYPTO_PUBLICKEYBYTES 1047319
#define PQCLEAN_MCELIECE6960119_AVX_CRYPTO_SECRETKEYBYTES 13908
#define PQCLEAN_MCELIECE6960119_AVX_CRYPTO_CIPHERTEXTBYTES 226
#define PQCLEAN_MCELIECE6960119_AVX_CRYPTO_BYTES 32


int PQCLEAN_MCELIECE6960119_AVX_crypto_kem_enc(
    uint8_t *c,
    uint8_t *key,
    const uint8_t *pk,
    const uint8_t *coins
);

int PQCLEAN_MCELIECE6960119_AVX_crypto_kem_dec(
    uint8_t *key,
    const uint8_t *c,
    const uint8_t *sk
);

int PQCLEAN_MCELIECE6960119_AVX_crypto_kem_keypair
(
    uint8_t *pk,
    uint8_t *sk
);

void PQCLEAN_MCELIECE6960119_AVX_crypto_kem_gen_e
(
    uint8_t *e
);

#endif
