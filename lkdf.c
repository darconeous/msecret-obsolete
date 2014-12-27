
#include "lkdf.h"
#include "hmac_sha/hmac_sha256.h"
#include <arpa/inet.h>
#include <string.h>

void
LKDF_extract(
	uint8_t *key_out, size_t key_size,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size,
	const uint8_t *ikm, size_t ikm_size
) {
	static const zero = 0;

	uint8_t t[HMAC_SHA256_DIGEST_LENGTH];
	uint32_t n;
	HMAC_SHA256_CTX hmac;

	for(n = 1 ; key_size != 0 ; n++) {
		const uint32_t be_n = htonl(n);
		int i;

		HMAC_SHA256_Init(&hmac);
		for( i = 0; i < (HMAC_SHA256_BLOCK_LENGTH - salt_size) ; i++) {
			HMAC_SHA256_UpdateKey(&hmac, &zero, 1);
		}
		HMAC_SHA256_UpdateKey(&hmac, salt, salt_size);
		HMAC_SHA256_UpdateKey(&hmac, info, info_size);
		HMAC_SHA256_UpdateKey(&hmac, (uint8_t*)&be_n, sizeof(be_n));
		HMAC_SHA256_EndKey(&hmac);

		HMAC_SHA256_StartMessage(&hmac);
		HMAC_SHA256_UpdateMessage(&hmac, t, n > 1 ? sizeof(t) : 0);
		HMAC_SHA256_UpdateMessage(&hmac, ikm, ikm_size);
		HMAC_SHA256_EndMessage(t, &hmac);

		if (key_size >= HMAC_SHA256_DIGEST_LENGTH) {
			memcpy(key_out, t, HMAC_SHA256_DIGEST_LENGTH);
			key_size -= HMAC_SHA256_DIGEST_LENGTH;
			key_out += HMAC_SHA256_DIGEST_LENGTH;
		} else {
			memcpy(key_out, t, key_size);
			key_size = 0;
		}
	}

	memset(t, 0, sizeof(t));
	HMAC_SHA256_Done(&hmac);
}


#if UNIT_TEST
#include <stdio.h>

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
		static const uint8_t master_secret[512];
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[16] = { 0 };

		LKDF_extract(
			key_out, sizeof(key_out),
			NULL, 0,
			(const uint8_t*)info, sizeof(info),
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "key_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
	{
		static const uint8_t master_secret[512];
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[48] = { 0 };

		LKDF_extract(
			key_out, sizeof(key_out),
			NULL, 0,
			(const uint8_t*)info, sizeof(info),
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "key_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
	{
		static const uint8_t master_secret[512] = { 1 };
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[48] = { 0 };

		LKDF_extract(
			key_out, sizeof(key_out),
			NULL, 0,
			(const uint8_t*)info, sizeof(info),
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "key_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
}

#endif


