
#include <assert.h>
#include <stdbool.h>
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

void
MSECRET_Extract_Integer_BN(
	BIGNUM *val,
	const BIGNUM *max,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	int size = BN_num_bytes(max);
	uint8_t val_bytes[size];
	uint8_t max_bytes[size];
	BN_bn2bin(max, max_bytes);
	MSECRET_Extract_Integer(
		val_bytes,
		max_bytes,
		size,
		key_selector,
		ikm,ikm_size
	);
	BN_bin2bn(val_bytes, size, val);
}

void
MSECRET_Extract_Prime_BN(
	BIGNUM *prime,
	int bit_length,
	int flags,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	MSECRET_KeySelector new_key_selector;
	HMAC_SHA256_CTX hmac;
	BIGNUM *max = BN_new();
	BIGNUM *e = NULL;
	uint32_t bit_length_be = htonl(bit_length);
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *r0 = BN_new();
	BIGNUM *r1 = BN_new();

	HMAC_SHA256_Init(&hmac);
	HMAC_SHA256_UpdateKey(&hmac, key_selector, sizeof(MSECRET_KeySelector));
	HMAC_SHA256_EndKey(&hmac);
	HMAC_SHA256_StartMessage(&hmac);
	HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"Prime:", 6);
	if (flags & MSECRET_PRIME_STD_EXPONENT) {
		e = BN_new();
		BN_set_word(e, RSA_F4);
		HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"GCD65537=0:", 7);
	}
#if MSECRET_PRIME_LEELIM
	if (flags & MSECRET_PRIME_LEELIM) {
		HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"LeeLim:", 7);
	}
#endif
	HMAC_SHA256_UpdateMessage(&hmac, (uint8_t*)&bit_length_be, sizeof(bit_length_be));
	HMAC_SHA256_EndMessage(new_key_selector, &hmac);

	BN_set_bit(max, bit_length);
	BN_sub_word(max, 1);

	MSECRET_Extract_Integer_BN(
		prime,
		max,
		new_key_selector,
		ikm, ikm_size
	);

	BN_set_bit(prime, 0);
	BN_set_bit(prime, bit_length-1);
	BN_set_bit(prime, bit_length-2);

	for(;true;BN_add_word(prime, 2)) {
		if (!BN_is_prime(prime, BN_prime_checks, NULL, ctx, NULL)) {
			continue;
		}

#if MSECRET_PRIME_LEELIM
        if (flags & MSECRET_PRIME_LEELIM) {
			// TODO: Check that the prime is a "Lee/Lim" prime.
		}
#endif

		if (e != NULL) {
			BN_sub(r0,prime,BN_value_one());
			BN_gcd(r1,r0,e,ctx);
			if (!BN_is_one(r1)) {
				fprintf(stderr,"Note: Skipped prime where (p-1) was divisible by 65537\n");
				continue;
			}
		}

		break;
	}

	if (e) {
		BN_free(e);
	}
	BN_free(r0);
	BN_free(r1);
	BN_free(max);
	BN_CTX_free(ctx);
}


void
MSECRET_Extract_RSA_X931(
	RSA *rsa,
	int mod_length,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	MSECRET_KeySelector new_key_selector;
	int bitsp, bitsq;
	int i;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *xp[3] = { BN_CTX_get(ctx), BN_CTX_get(ctx), BN_CTX_get(ctx) };
	BIGNUM *xq[3] = { BN_CTX_get(ctx), BN_CTX_get(ctx), BN_CTX_get(ctx) };
	BIGNUM *max = BN_CTX_get(ctx);
	BIGNUM *max101 = BN_CTX_get(ctx);

	bitsp = (mod_length+1)/2;
	bitsq = mod_length-bitsp;

	if (rsa->e == NULL) {
		rsa->e = BN_new();
		BN_set_word(rsa->e, RSA_F4);
	}

	BN_set_bit(max101, 102);
	BN_sub_word(max101, 1);

	BN_set_bit(max, bitsp);
	BN_sub_word(max, 1);

	for(i=0; i<3; i++) {
		char sel_str[] = "Xp0";
		sel_str[2] += i;
		MSECRET_CalcKeySelector(
			new_key_selector,
			key_selector, sizeof(MSECRET_KeySelector),
			sel_str, 0
		);

		MSECRET_Extract_Integer_BN(
			xp[i],
			(i==0)?max:max101,
			new_key_selector,
			ikm, ikm_size
		);
	}
	BN_set_bit(xp[0], 0);
	BN_set_bit(xp[0], bitsp-1);
	BN_set_bit(xp[0], bitsp-2);

	BN_zero(max);
	BN_set_bit(max, bitsq);
	BN_sub_word(max, 1);

	for(i=0; i<3; i++) {
		char sel_str[] = "Xq0";
		sel_str[2] += i;
		MSECRET_CalcKeySelector(
			new_key_selector,
			key_selector, sizeof(MSECRET_KeySelector),
			sel_str, 0
		);

		MSECRET_Extract_Integer_BN(
			xq[i],
			(i==0)?max:max101,
			new_key_selector,
			ikm, ikm_size
		);
	}
	BN_set_bit(xq[0], 0);
	BN_set_bit(xq[0], bitsq-1);
	BN_set_bit(xq[0], bitsq-2);

	RSA_X931_derive_ex(
		rsa,
		NULL, NULL,
		NULL, NULL,
		xp[1], xp[2], xp[0],
		xq[1], xq[2], xq[0],
		rsa->e,
		NULL
	);

	BN_CTX_free(ctx);
}



void
MSECRET_Extract_RSA(
	RSA *rsa,
	int mod_length,
	int flags,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	// TODO: Review http://www.opensource.apple.com/source/OpenSSL097/OpenSSL097-16/openssl/crypto/rsa/rsa_gen.c
	uint32_t salt = 0, be_salt = 0;
	MSECRET_KeySelector new_key_selector;
	int bitsp, bitsq;
	HMAC_SHA256_CTX hmac;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *r0 = BN_new();
	BIGNUM *r1 = BN_new();
	BIGNUM *r2 = BN_new();
	BIGNUM *r3 = BN_new();

	bitsp = (mod_length+1)/2;
	bitsq = mod_length-bitsp;

	if (rsa->p == NULL) {
		rsa->p = BN_new();
	}

	if (rsa->q == NULL) {
		rsa->q = BN_new();
	}

	if (rsa->e == NULL) {
		rsa->e = BN_new();
		BN_set_word(rsa->e, RSA_F4);
	}

	MSECRET_CalcKeySelector(
		new_key_selector,
		key_selector, sizeof(MSECRET_KeySelector),
		"RSAPrivateKey:p", 0
	);

	MSECRET_Extract_Prime_BN(
		rsa->p,
		bitsp,
		flags | MSECRET_PRIME_STD_EXPONENT,
		new_key_selector,
		ikm, ikm_size
	);

	MSECRET_CalcKeySelector(
		new_key_selector,
		key_selector, sizeof(MSECRET_KeySelector),
		"RSAPrivateKey:q", 0
	);

	MSECRET_Extract_Prime_BN(
		rsa->q,
		bitsq,
		flags | MSECRET_PRIME_STD_EXPONENT,
		new_key_selector,
		ikm, ikm_size
	);

	assert(BN_cmp(rsa->p,rsa->q) != 0);

	// P should be the larger of the two, by convention.
	if (BN_cmp(rsa->p,rsa->q) < 0)
	{
		BIGNUM *tmp=rsa->p;
		rsa->p=rsa->q;
		rsa->q=tmp;
	}

	// Derive the rest.
	RSA_X931_derive_ex(
		rsa,
		NULL, NULL,
		NULL, NULL,
		NULL, NULL, NULL,
		NULL, NULL, NULL,
		rsa->e,
		NULL
	);

	BN_CTX_free(ctx);
}

void
MSECRET_Extract_Integer(
	uint8_t *key_out,
	const uint8_t *max_in, size_t mod_size,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	uint32_t salt = 0, be_salt = 0;
	MSECRET_KeySelector new_key_selector;
	HMAC_SHA256_CTX hmac;

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

		HMAC_SHA256_Init(&hmac);
		HMAC_SHA256_UpdateKey(&hmac, key_selector, sizeof(MSECRET_KeySelector));
		HMAC_SHA256_EndKey(&hmac);
		HMAC_SHA256_StartMessage(&hmac);
		HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"Integer:", 7);
		HMAC_SHA256_UpdateMessage(&hmac, max_in, mod_size);
		HMAC_SHA256_UpdateMessage(&hmac, (uint8_t*)&be_salt, sizeof(be_salt));
		HMAC_SHA256_EndMessage(new_key_selector, &hmac);

		MSECRET_Extract_Bytes(
			key_out, mod_size,
			new_key_selector,
			ikm, ikm_size
		);

		// Mask the unnecessary bits of the first
		// byte. This makes the search faster.
		key_out[0] &= enclosing_mask_uint8(max_in[0]);

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
