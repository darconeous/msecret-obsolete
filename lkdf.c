
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


void LKDF_SHA256_CalcKeySelector(
	LKDF_SHA256_KeySelector key_out,
	const uint8_t *salt, size_t salt_size,
	const uint8_t *info, size_t info_size
) {
	 /*
	  * LKDF_CalcKeySelector(salt, info) -> selector
	  * LKDF_CalcKeySelector(salt, info) = HMAC_Hash(salt, info)
	  */
	HMAC_SHA256_CTX hmac;

	HMAC_SHA256_Init(&hmac);
	HMAC_SHA256_UpdateKey(&hmac, salt, salt_size);
	HMAC_SHA256_EndKey(&hmac);
	HMAC_SHA256_StartMessage(&hmac);
	HMAC_SHA256_UpdateMessage(&hmac, info, info_size);
	HMAC_SHA256_EndMessage(key_out, &hmac);

	HMAC_SHA256_Done(&hmac);
}

void LKDF_SHA256_Extract(
	uint8_t *key_out, size_t key_size,
	const LKDF_SHA256_KeySelector keySelector,
	const uint8_t *ikm, size_t ikm_size
) {
	/* If the IKM size is less than HMAC_DigestLength, then:
	 *
	 *     LKDF_Extract(selector, IKM, L) =
	 *             HKDF_Expand(HKDF_Extract(selector, IKM), "", L)
	 *
	 * If the IKM size is greater than HMAC_DigestLength, then
	 * things are much more complicated.
	 */

	uint8_t buf[HMAC_SHA256_DIGEST_LENGTH];
	uint32_t n = 0;
	HMAC_SHA256_CTX hmac;

#ifdef LKDF_DEBUG
	fprintf(stderr, "key_size: %d\n", (int)key_size);
	fprintf(stderr, "ikm_size: %d\n", (int)ikm_size);
#endif

	if (ikm_size <= sizeof(buf)) {
		// HKDF: Derive PRK
		HMAC_SHA256_Init(&hmac);
		HMAC_SHA256_UpdateKey(&hmac, keySelector, sizeof(buf));
		HMAC_SHA256_EndKey(&hmac);
		HMAC_SHA256_StartMessage(&hmac);
		HMAC_SHA256_UpdateMessage(&hmac, ikm, ikm_size);
		HMAC_SHA256_EndMessage(buf, &hmac);

		// HKDF: Load PRK
		HMAC_SHA256_Init(&hmac);
		HMAC_SHA256_UpdateKey(&hmac, buf, sizeof(buf));
		HMAC_SHA256_EndKey(&hmac);

		// HKDF: Loop until key output is filled.
		do {
			n++;
			uint8_t c = (uint8_t)n;
			HMAC_SHA256_StartMessage(&hmac);
			if (n != 1) {
				HMAC_SHA256_UpdateMessage(&hmac, buf, sizeof(buf));
			}
			HMAC_SHA256_UpdateMessage(&hmac, &c, 1);
			HMAC_SHA256_EndMessage(buf, &hmac);

			if (key_size >= sizeof(buf)) {
				memcpy(key_out, buf, sizeof(buf));
				key_out += sizeof(buf);
				key_size -= sizeof(buf);
			} else {
				memcpy(key_out, buf, key_size);
				key_size = 0;
			}
		} while(key_size > 0);

	} else {

		// --------------------------------------------------------
		// Load the selector as the new key

		HMAC_SHA256_Init(&hmac);
		HMAC_SHA256_UpdateKey(&hmac, keySelector, HMAC_SHA256_DIGEST_LENGTH);
		HMAC_SHA256_EndKey(&hmac);

		// --------------------------------------------------------
		// Output key generation loop

		for (n = 1 ; key_size != 0 ; n++) {
			int output_block_size;
			int ikm_left, ikm_n;
			const uint8_t* ikm_idx;
			const uint8_t cn = (uint8_t)n;

			if (key_size > sizeof(buf)) {
				output_block_size = sizeof(buf);
			} else {
				output_block_size = key_size;
			}

			// Initialize the output to all zeros.
			memset(key_out, 0, output_block_size);

			// Interate through each block of the IKM.
			for (	ikm_idx = ikm,
					ikm_left = ikm_size,
					ikm_n = 1
				;	(ikm_left > 0) || (ikm_n == 1)
				;	ikm_left -= sizeof(buf),
					ikm_idx += sizeof(buf),
					ikm_n++
			) {
				const uint8_t ikm_cn = (uint8_t)ikm_n;

				HMAC_SHA256_StartMessage(&hmac);

				// Output feedback from previous output key block
				HMAC_SHA256_UpdateMessage(
					&hmac,
					key_out - sizeof(buf),
					(n > 1)
						? sizeof(buf)
						: 0
				);

				// Output key block index
				HMAC_SHA256_UpdateMessage(
					&hmac,
					&cn,
					1
				);

				// Data from IKM block
				HMAC_SHA256_UpdateMessage(
					&hmac,
					ikm_idx,
					(ikm_left > sizeof(buf))
						? sizeof(buf)
						: ikm_left
				);

				// IKM block counter
				HMAC_SHA256_UpdateMessage(
					&hmac,
					&ikm_cn,
					1
				);

				HMAC_SHA256_EndMessage(buf, &hmac);

				// XOR the results for each block into the output.
				xorcpy(key_out, buf, output_block_size);
			}

			key_size -= output_block_size;
			key_out += output_block_size;
		}
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
		static const uint8_t master_secret[0]; // Empty master secret
		static const char info[] = "LKDF Test Vector";
		uint8_t key_out[16] = { 0 };
		LKDF_SHA256_KeySelector keySelector;

		LKDF_SHA256_CalcKeySelector(
			keySelector,
			NULL, 0,
			(const uint8_t*)info, strlen(info)
		);

		LKDF_SHA256_Extract(
			key_out, sizeof(key_out),
			keySelector,
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "Empty master secret, empty salt\n");
		fprintf(stdout, "\tkey_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
	{
		static const uint8_t master_secret[512]; // All zeros
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[16] = { 0 };

		LKDF_SHA256_KeySelector keySelector;

		LKDF_SHA256_CalcKeySelector(
			keySelector,
			NULL, 0,
			(const uint8_t*)info, strlen(info)
		);

		LKDF_SHA256_Extract(
			key_out, sizeof(key_out),
			keySelector,
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "Master secret with 512 zeros, empty salt\n");
		fprintf(stdout, "\tkey_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
	{
		static const uint8_t master_secret[512]; // All zeros
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[48] = { 0 };
		LKDF_SHA256_KeySelector keySelector;

		LKDF_SHA256_CalcKeySelector(
			keySelector,
			NULL, 0,
			(const uint8_t*)info, strlen(info)
		);

		LKDF_SHA256_Extract(
			key_out, sizeof(key_out),
			keySelector,
			master_secret, sizeof(master_secret)
		);
		fprintf(stdout, "Master secret with 512 zeros, empty salt\n");
		fprintf(stdout, "\tkey_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
	{
		static const uint8_t master_secret[512] = { 0x80 }; // MSB set, rest zeros
		static const char info[] = "LKDF Test Vector";

		uint8_t key_out[48] = { 0 };
		LKDF_SHA256_KeySelector keySelector;

		LKDF_SHA256_CalcKeySelector(
			keySelector,
			NULL, 0,
			(const uint8_t*)info, strlen(info)
		);

		LKDF_SHA256_Extract(
			key_out, sizeof(key_out),
			keySelector,
			master_secret, sizeof(master_secret)
		);

		fprintf(stdout, "Master secret with 0x80 and 511 zeros, empty salt\n");
		fprintf(stdout, "\tkey_out = ");
		hex_dump(stdout, key_out, sizeof(key_out));
		fprintf(stdout, "\n");
	}
}

#endif


