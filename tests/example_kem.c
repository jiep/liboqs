/*
 * example_kem.c
 *
 * Minimal example of a Diffie-Hellman-style post-quantum key encapsulation
 * implemented in liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>


void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem, uint8_t *shared_secret_d2);

void print_hex(const uint8_t *bytes, size_t length) {
  for(size_t i = 0; i < length; i++){
    printf("%02x", bytes[i]);
  }
  printf("\n");
}

/* This function gives an example of the operations performed by both
 * the decapsulator and the encapsulator in a single KEM session,
 * allocating variables dynamically on the heap and calling the generic
 * OQS_KEM object.
 *
 * This does not require the use of compile-time macros to check if the
 * algorithm in question was enabled at compile-time; instead, the caller
 * must check that the OQS_KEM object returned is not NULL.
 */
static OQS_STATUS example_heap(void) {
	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
  uint8_t *ciphertext = NULL;
  uint8_t *ciphertext2 = NULL;
	uint8_t *shared_secret_e = NULL;
  uint8_t *shared_secret_d = NULL;
  uint8_t *shared_secret_d2 = NULL;
  uint8_t *coins = NULL;

	kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_460896f);
	if (kem == NULL) {
		printf("[example_heap]  OQS_KEM_alg_classic_mceliece_460896f was not enabled at "
		       "compile-time.\n");
		return OQS_ERROR;
	}

	public_key = malloc(kem->length_public_key);
	secret_key = malloc(kem->length_secret_key);
  ciphertext = malloc(kem->length_ciphertext);
  ciphertext2 = malloc(kem->length_ciphertext);
	shared_secret_e = malloc(kem->length_shared_secret);
	shared_secret_d = malloc(kem->length_shared_secret);
  shared_secret_d2 = malloc(kem->length_shared_secret);
  coins = malloc(kem->length_coins);
	if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) ||
	        (shared_secret_e == NULL) || (shared_secret_d == NULL) || (shared_secret_d2 == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem, shared_secret_d2);

    free(coins);
		return OQS_ERROR;
	}

	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem, shared_secret_d2);

		return OQS_ERROR;
	}
  kem->gen_e(coins);
  printf("coins: ");
  print_hex(coins, kem->length_coins);
  rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key, coins);
  rc = OQS_KEM_encaps(kem, ciphertext2, shared_secret_d, public_key, coins);
  printf("ciphertext:  ");
  print_hex(ciphertext, kem->length_ciphertext);
  printf("ciphertext2: ");
  print_hex(ciphertext2, kem->length_ciphertext);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem, shared_secret_d2);

		return OQS_ERROR;
	}
	rc = OQS_KEM_decaps(kem, shared_secret_d2, ciphertext, secret_key);
  printf("shared_secret_d:  ");
  print_hex(shared_secret_d, kem->length_shared_secret);
  printf("shared_secret_d2: ");
  print_hex(shared_secret_d2, kem->length_shared_secret);
  printf("rc: %d\n", rc);
	if (rc != OQS_SUCCESS || memcmp(shared_secret_d, shared_secret_d2, kem->length_shared_secret) != 0) {
		fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
		cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
		             ciphertext, kem, shared_secret_d2);

		return OQS_ERROR;
	}

	printf("[example_heap] OQS_KEM_alg_classic_mceliece_460896f operations completed.\n");
	cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key,
	             ciphertext, kem, shared_secret_d2);

	return OQS_SUCCESS; // success
}

int main(void) {
	if (example_heap() == OQS_SUCCESS) {
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem, uint8_t *shared_secret_d2) {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_d2, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}
