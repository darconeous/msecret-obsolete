


#ifndef __MASTER_SECRET_LKDF_H__
#define __MASTER_SECRET_LKDF_H__ 1

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "hmac_sha256.h"

typedef uint8_t LKDF_SHA256_KeySelector[HMAC_SHA256_DIGEST_LENGTH];

void LKDF_SHA256_CalcKeySelector(
	LKDF_SHA256_KeySelector key_out,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size
);

void LKDF_SHA256_Extract(
	uint8_t *key_out, size_t key_size,
	const LKDF_SHA256_KeySelector keySelector,
	const uint8_t *ikm, size_t ikm_size
);

#endif
