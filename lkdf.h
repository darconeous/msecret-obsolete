


#ifndef __MASTER_SECRET_LKDF_H__
#define __MASTER_SECRET_LKDF_H__ 1

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

void LKDF_SHA256_extract(
	uint8_t *key_out, size_t key_size,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size,
	const uint8_t *ikm, size_t ikm_size
);

int LKDF_SHA256_ExtractToFILE(
	FILE* key_file, size_t key_size,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size,
	const uint8_t *ikm, size_t ikm_size
);

#endif
