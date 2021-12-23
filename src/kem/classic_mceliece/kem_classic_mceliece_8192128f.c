// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_classic_mceliece.h>

#if defined(OQS_ENABLE_KEM_classic_mceliece_8192128f)

OQS_KEM *OQS_KEM_classic_mceliece_8192128f_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_classic_mceliece_8192128f;
	kem->alg_version = "SUPERCOP-20191221";

	kem->claimed_nist_level = 5;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_classic_mceliece_8192128f_length_public_key;
	kem->length_secret_key = OQS_KEM_classic_mceliece_8192128f_length_secret_key;
	kem->length_ciphertext = OQS_KEM_classic_mceliece_8192128f_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_classic_mceliece_8192128f_length_shared_secret;
	kem->length_coins = OQS_KEM_classic_mceliece_8192128f_length_coins;

	kem->keypair = OQS_KEM_classic_mceliece_8192128f_keypair;
	kem->encaps = OQS_KEM_classic_mceliece_8192128f_encaps;
	kem->decaps = OQS_KEM_classic_mceliece_8192128f_decaps;
	kem->gen_e = OQS_KEM_classic_mceliece_8192128f_gen_e;

	return kem;
}

extern int PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
extern int PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern void PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_gen_e(uint8_t *e);

#if defined(OQS_ENABLE_KEM_classic_mceliece_8192128f_avx)
extern int PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
extern int PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern void PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_gen_e(uint8_t *e);
#endif

OQS_API OQS_STATUS OQS_KEM_classic_mceliece_8192128f_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_classic_mceliece_8192128f_avx)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_classic_mceliece_8192128f_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const uint8_t *coins) {
#if defined(OQS_ENABLE_KEM_classic_mceliece_8192128f_avx)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_enc(ciphertext, shared_secret, public_key, coins);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_enc(ciphertext, shared_secret, public_key, coins);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_enc(ciphertext, shared_secret, public_key, coins);
#endif
}

OQS_API OQS_STATUS OQS_KEM_classic_mceliece_8192128f_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_classic_mceliece_8192128f_avx)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI1)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#endif
}

OQS_API void OQS_KEM_classic_mceliece_8192128f_gen_e(uint8_t *e) {
#if defined(OQS_ENABLE_KEM_classic_mceliece_8192128_avx)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		PQCLEAN_MCELIECE8192128F_AVX_crypto_kem_gen_e(e);
#if defined(OQS_DIST_BUILD)
	} else {
		PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_gen_e(e);
	}
#endif /* OQS_DIST_BUILD */
#else
	PQCLEAN_MCELIECE8192128F_VEC_crypto_kem_gen_e(e);
#endif
}

#endif
