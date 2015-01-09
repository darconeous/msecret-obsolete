
#include <assert.h>
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



void
MSECRET_CalcKeySelector(
	MSECRET_KeySelector keySelector_out,
	const uint8_t *salt, size_t salt_size,
	const char *info, size_t info_size
) {
	if ((info != NULL) && (info_size == 0)) {
		info_size = strlen(info);
	}
	return LKDF_SHA256_CalcKeySelector(keySelector_out,salt,salt_size,(const uint8_t*)info, info_size);
}

void MSECRET_Extract_Bytes(
	uint8_t *key_out, size_t key_size,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	LKDF_SHA256_Extract(
		key_out, key_size,
		key_selector,
		ikm, ikm_size
	);
}

void MSECRET_Extract_Integer(
	uint8_t *key_out,
	const uint8_t *max_in, size_t mod_size,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	uint32_t salt = 0, be_salt = 0;
	MSECRET_KeySelector new_key_selector;

	// Cancel out the initial increment in the loop.
	salt--;

	// Skip any leading zero bytes in the modulous
	while(mod_size && (*max_in == 0)) {
		*key_out++ = 0;
		max_in++;
		mod_size--;
	}

	// Search for a key which satisfies the modulous
	do {
		salt++;
		be_salt = htonl(salt);

		if (salt == 0) {
			// For the first try we just pass it thru
			memcpy(new_key_selector, key_selector, sizeof(new_key_selector));
		} else {
			MSECRET_CalcKeySelector(
				new_key_selector,
				(uint8_t*)&be_salt, sizeof(be_salt),
				(const char*)key_selector, sizeof(MSECRET_KeySelector)
			);
		}
		MSECRET_Extract_Bytes(
			key_out, mod_size,
			new_key_selector,
			ikm, ikm_size
		);

		// Mask the unnecessary bits of the first
		// byte. This makes the search faster.
		key_out[0] &= enclosing_mask_uint8(max_in[0]);

		assert(salt < 2048);
	} while( memcmp(key_out, max_in, mod_size) > 0 );
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
		static const uint8_t master_secret[512] = {0};
		static const char info[] = "MSECRET Test Vector";

		uint8_t key_out[16] = { 0 };
		uint8_t max_in[16] = { 0, 0x08, 0xFF };
		MSECRET_KeySelector key_selector;

		MSECRET_CalcKeySelector(
			key_selector,
			NULL, 0,
			info, 0
		);

		MSECRET_Extract_Integer(
			key_out, max_in, sizeof(max_in),
			key_selector,
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "max_in  = ");
		hex_dump(stdout, max_in, sizeof(max_in));
		fprintf(stdout, "\n");
		fprintf(stdout, "key_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
}

#endif
