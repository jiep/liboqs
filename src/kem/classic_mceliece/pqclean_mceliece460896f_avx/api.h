#ifndef PQCLEAN_MCELIECE460896F_AVX_API_H
#define PQCLEAN_MCELIECE460896F_AVX_API_H

#include <stdint.h>

#define PQCLEAN_MCELIECE460896F_AVX_CRYPTO_ALGNAME "Classic McEliece 460896f"
#define PQCLEAN_MCELIECE460896F_AVX_CRYPTO_PUBLICKEYBYTES 524160
#define PQCLEAN_MCELIECE460896F_AVX_CRYPTO_SECRETKEYBYTES 13568
#define PQCLEAN_MCELIECE460896F_AVX_CRYPTO_CIPHERTEXTBYTES 188
#define PQCLEAN_MCELIECE460896F_AVX_CRYPTO_BYTES 32

int PQCLEAN_MCELIECE460896F_AVX_crypto_kem_enc(
    uint8_t *c,
    uint8_t *key,
    const uint8_t *pk,
    const uint8_t *coins
);

int PQCLEAN_MCELIECE460896F_AVX_crypto_kem_dec(
    uint8_t *key,
    const uint8_t *c,
    const uint8_t *sk
);

int PQCLEAN_MCELIECE460896F_AVX_crypto_kem_keypair
(
    uint8_t *pk,
    uint8_t *sk
);

void PQCLEAN_MCELIECE460896F_AVX_crypto_kem_gen_e
(
    uint8_t *e
);

#endif
