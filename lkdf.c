
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
	uint8_t buf[HMAC_SHA256_DIGEST_LENGTH];
	uint32_t n;
	HMAC_SHA256_CTX hmac;

/*
	fprintf(stderr, "key_size: %d\n", (int)key_size);
	fprintf(stderr, "salt_size: %d\n", (int)salt_size);
	fprintf(stderr, "info_size: %d\n", (int)info_size);
	fprintf(stderr, "ikm_size: %d\n", (int)ikm_size);
*/

	// --------------------------------------------------------
	// Calculate selector --- `HMAC(salt, info)`

	HMAC_SHA256_Init(&hmac);

	// Zero-fill the most-significant (left-most) bits for the salt.
	for( n = 0; n < (HMAC_SHA256_DIGEST_LENGTH - salt_size) ; n++) {
		static const uint8_t zero = 0;
		HMAC_SHA256_UpdateKey(&hmac, &zero, 1);
	}

	HMAC_SHA256_UpdateKey(&hmac, salt, salt_size);
	HMAC_SHA256_EndKey(&hmac);
	HMAC_SHA256_StartMessage(&hmac);
	HMAC_SHA256_UpdateMessage(&hmac, info, info_size);

	// Selector is now in `buf`.
	HMAC_SHA256_EndMessage(buf, &hmac);

	// --------------------------------------------------------
	// Load the selector as the new key

	HMAC_SHA256_Init(&hmac);
	HMAC_SHA256_UpdateKey(&hmac, buf, HMAC_SHA256_DIGEST_LENGTH);
	HMAC_SHA256_EndKey(&hmac);

	// --------------------------------------------------------
	// Output key generation loop

	for(n = 1 ; key_size != 0 ; n++) {
		int i, output_block_size;
		int ikm_left, ikm_n;
		const uint8_t* ikm_idx;

		// Integer values must be in big-endian when included in hash.
		const uint32_t be_n = htonl(n);

		if (key_size > HMAC_SHA256_DIGEST_LENGTH) {
			output_block_size = HMAC_SHA256_DIGEST_LENGTH;
		} else {
			output_block_size = key_size;
		}

		// Initialize the output to all zeros.
		memset(key_out, 0, output_block_size);

		// Interate through each block of the IKM.
		for (	ikm_idx=ikm,
				ikm_left=ikm_size,
				ikm_n=0
			;	ikm_left > 0
			;	ikm_left -= HMAC_SHA256_DIGEST_LENGTH,
				ikm_idx += HMAC_SHA256_DIGEST_LENGTH,
				ikm_n++
		) {
			// Integer values must be in big-endian when included in hash.
			const uint32_t be_ikm_n = htonl(ikm_n);

			HMAC_SHA256_StartMessage(&hmac);

			// Output feedback from previous output key block
			HMAC_SHA256_UpdateMessage(&hmac, key_out - HMAC_SHA256_DIGEST_LENGTH, n > 1 ? sizeof(buf) : 0);

			// IKM block counter (Big-endian)
			HMAC_SHA256_UpdateMessage(&hmac, (uint8_t*)&ikm_n, sizeof(ikm_n));

			// Data from IKM block
			HMAC_SHA256_UpdateMessage(&hmac, ikm_idx, ikm_left>HMAC_SHA256_DIGEST_LENGTH?HMAC_SHA256_DIGEST_LENGTH:ikm_left);

			// Output key block index (Big-endian)
			HMAC_SHA256_UpdateMessage(&hmac, (uint8_t*)&be_n, sizeof(be_n));

			HMAC_SHA256_EndMessage(buf, &hmac);

			// XOR the results for each block into the output.
			xorcpy(key_out, buf, output_block_size);
		}

		key_size -= output_block_size;
		key_out += output_block_size;
	}

	memset(buf, 0, sizeof(buf));
	HMAC_SHA256_Done(&hmac);
}

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
			(const uint8_t*)info, strlen(info),
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
			(const uint8_t*)info, strlen(info),
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
			(const uint8_t*)info, strlen(info),
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "key_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
}

#endif


