


#ifndef __MSECRET_H__
#define __MSECRET_H__ 1

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

void MSECRET_Extract(
	uint8_t *key_out, size_t key_size,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
);

int MSECRET_ExtractToFILE(
	FILE* key_file, size_t key_size,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
);

void MSECRET_ExtractMod(
	uint8_t *key_out,
	uint8_t *mod_in, size_t mod_size,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
);

#endif
