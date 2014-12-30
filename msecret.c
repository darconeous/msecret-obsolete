
#include "msecret.h"
#include "lkdf.h"
#include "hmac_sha/hmac_sha256.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

static uint8_t
enclosing_mask_uint8(uint8_t x) {
	x |= (x >> 1);
	x |= (x >> 2);
	x |= (x >> 4);
	return x;
}

static void
_MSECRET_Extract(
	uint8_t *key_out, size_t key_size,
	uint32_t salt,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
) {
	salt = htonl(salt);
	if (info == NULL) {
		info = "";
	}
	LKDF_SHA256_extract(
		key_out, key_size,
		(uint8_t*)&salt, sizeof(salt),
		(const uint8_t*)info, strlen(info),
		ikm, ikm_size
	);
}

int
MSECRET_ExtractToFILE(
	FILE* key_file, size_t key_size,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
) {
	if (info == NULL) {
		info = "";
	}
	return LKDF_SHA256_ExtractToFILE(
		key_file, key_size,
		NULL, 0,
		(const uint8_t*)info, strlen(info),
		ikm, ikm_size
	);
}

void
MSECRET_Extract(
	uint8_t *key_out, size_t key_size,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
) {
	_MSECRET_Extract(
		key_out, key_size,
		0,
		info,
		ikm, ikm_size
	);
}

void
MSECRET_ExtractMod(
	uint8_t *key_out,
	uint8_t *mod_in, size_t mod_size,
	const char *info,
	const uint8_t *ikm, size_t ikm_size
) {
	uint32_t salt = 0;

	// Cancel out the initial increment in the loop.
	salt--;

	// Skip any leading zero bytes in the modulous
	while(mod_size && (*mod_in == 0)) {
		*key_out++ = 0;
		mod_in++;
		mod_size--;
	}

	// Search for a key which satisfies the modulous
	do {
		salt++;
		_MSECRET_Extract(
			key_out, mod_size,
			salt,
			info,
			ikm, ikm_size
		);

		// Mask the unnecessary bits of the first
		// byte. This makes the search faster.
		key_out[0] &= enclosing_mask_uint8(mod_in[0]);
	} while( memcmp(key_out, mod_in, mod_size) > 0 );
}

#if MSECRET_UNIT_TEST

int
hex_dump(FILE* file, const uint8_t *data, size_t data_len)
{
	int ret = 0;
	while(data_len > 0) {
		int i = 0;
		if (data_len == 1) {
			i = fprintf(file,"%02X",*data);
		} else {
			i = fprintf(file, "%02X ",*data);
		}
		if (i < 0) {
			ret = i;
		}
		if (i <= 0) {
			break;
		}
		ret += i;
		data_len--;
		data++;
	}
	return ret;
}

int
main(void) {
	{
		static const uint8_t master_secret[512] = {5};
		static const char info[] = "MSECRET Test Vector";

		uint8_t key_out[16] = { 0 };
		uint8_t mod_in[16] = { 0, 0x08, 0xFF };

		MSECRET_ExtractMod(
			key_out, mod_in, sizeof(mod_in),
			info,
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "mod_in  = ");
		hex_dump(stdout, mod_in, sizeof(mod_in));
		fprintf(stdout, "\n");
		fprintf(stdout, "key_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
}

#endif
