
#include "lkdf.h"
#include "hmac_sha/hmac_sha256.h"
#include <arpa/inet.h>
#include <string.h>

static void *
xorcpy(void *restrict dst, const void *restrict src, size_t n)
{
	uint8_t* idx = (uint8_t*)dst;
	for (; n != 0 ; n--) {
		*idx++ ^= *(const uint8_t*)src++;
	}
	return dst;
}

void
LKDF_SHA256_extract(
	uint8_t *key_out, size_t key_size,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size,
	const uint8_t *ikm, size_t ikm_size
) {
	static const uint8_t zero = 0;

	uint8_t buf[HMAC_SHA256_DIGEST_LENGTH];
//	uint8_t selector[HMAC_SHA256_DIGEST_LENGTH];
	uint32_t n;
	HMAC_SHA256_CTX hmac;

	// Calculate selector
	HMAC_SHA256_Init(&hmac);
	for( n = 0; n < (HMAC_SHA256_DIGEST_LENGTH - salt_size) ; n++) {
		HMAC_SHA256_UpdateKey(&hmac, &zero, 1);
	}
	HMAC_SHA256_UpdateKey(&hmac, salt, salt_size);
	HMAC_SHA256_EndKey(&hmac);
	HMAC_SHA256_StartMessage(&hmac);
	HMAC_SHA256_UpdateMessage(&hmac, info, info_size);
	HMAC_SHA256_EndMessage(buf, &hmac);

//	xorcpy(selector, buf, sizeof(buf));

	// Load the selector as the new key
	HMAC_SHA256_Init(&hmac);
	HMAC_SHA256_UpdateKey(&hmac, buf, HMAC_SHA256_DIGEST_LENGTH);
	HMAC_SHA256_EndKey(&hmac);

	for(n = 1 ; key_size != 0 ; n++) {
		const uint32_t be_n = htonl(n);
		int i;
		int output_block_size;
		int ikm_left, ikm_n;
		const uint8_t* ikm_idx;

		if (key_size > HMAC_SHA256_DIGEST_LENGTH) {
			output_block_size = HMAC_SHA256_DIGEST_LENGTH;
		} else {
			output_block_size = key_size;
		}

		// Initialize the output to all zeros.
		memset(key_out, 0, output_block_size);

		// Interate through each block of the IKM.
		for (
			ikm_idx=ikm, ikm_left=ikm_size, ikm_n=0 ;
			ikm_left > 0 ;
			ikm_left -= HMAC_SHA256_DIGEST_LENGTH, ikm_idx += HMAC_SHA256_DIGEST_LENGTH, ikm_n++
		) {
			const uint32_t be_ikm_n = htonl(ikm_n);
			HMAC_SHA256_StartMessage(&hmac);
			HMAC_SHA256_UpdateMessage(&hmac, key_out - HMAC_SHA256_DIGEST_LENGTH, n > 1 ? sizeof(buf) : 0);
			HMAC_SHA256_UpdateMessage(&hmac, (uint8_t*)&ikm_n, sizeof(ikm_n));
			HMAC_SHA256_UpdateMessage(&hmac, ikm_idx, ikm_left>HMAC_SHA256_DIGEST_LENGTH?HMAC_SHA256_DIGEST_LENGTH:ikm_left);
			HMAC_SHA256_UpdateMessage(&hmac, (uint8_t*)&be_n, sizeof(be_n));
			HMAC_SHA256_EndMessage(buf, &hmac);

			// Mix each block into the output.
			xorcpy(key_out, buf, output_block_size);
		}

		key_size -= output_block_size;
		key_out += output_block_size;
	}

	memset(buf, 0, sizeof(buf));
	HMAC_SHA256_Done(&hmac);
}

/*
int
LKDF_SHA256_ExtractToFILE(
	FILE* key_file, size_t key_size,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size,
	const uint8_t *ikm, size_t ikm_size
) {
	static const uint8_t zero = 0;
	int ret = 0;
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
			int written;

			written = fwrite(t, 1, HMAC_SHA256_DIGEST_LENGTH, key_file);
			if (written<HMAC_SHA256_DIGEST_LENGTH) {
				ret = -1;
				goto bail;
			}
			ret += written;
			key_size -= HMAC_SHA256_DIGEST_LENGTH;
		} else {
			int written;

			written = fwrite(t, 1, key_size, key_file);
			if (written<key_size) {
				ret = -1;
				goto bail;
			}
			ret += written;
			key_size = 0;
		}
	}

bail:
	memset(t, 0, sizeof(t));
	HMAC_SHA256_Done(&hmac);
	return ret;
}
*/

#if LKDF_UNIT_TEST
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
		static const uint8_t master_secret[512]; // All zeros
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[16] = { 0 };

		LKDF_SHA256_extract(
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
		static const uint8_t master_secret[512]; // All zeros
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[48] = { 0 };

		LKDF_SHA256_extract(
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
		static const uint8_t master_secret[512] = { 0x80 }; // MSB set, rest zeros
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[48] = { 0 };

		LKDF_SHA256_extract(
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


