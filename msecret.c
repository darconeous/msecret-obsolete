
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
	return LKDF_SHA256_CalcKeySelector(
		keySelector_out,
		salt, salt_size,
		(const uint8_t*)info, info_size
	);
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
MSECRET_Extract_Integer(
	uint8_t *key_out,
	const uint8_t *max_in, size_t mod_size,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	MSECRET_KeySelector new_key_selector;

	// Copy over the key selector. We will end up
	// mutating this, possibly multiple times to
	// satisfy the maximum.
	memcpy(new_key_selector, key_selector, sizeof(MSECRET_KeySelector));

	// Skip any leading zero bytes in the modulous
	while (mod_size && (*max_in == 0)) {
		*key_out++ = 0;
		max_in++;
		mod_size--;
	}

	// Search for a key which satisfies the modulous
	// We can end up attempting this multiple times
	// in order to satisfy the modulus. This ensures
	// that we have a uniform distribution.
	do {
		MSECRET_CalcKeySelector(
			new_key_selector,
			new_key_selector, sizeof(MSECRET_KeySelector),
			(const char*)max_in, mod_size
		);

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
	static const int kSupportedFlags = 0
#if MSECRET_PRIME_LEELIM
		| MSECRET_PRIME_LEELIM
#endif
		| MSECRET_PRIME_STD_EXPONENT;

	MSECRET_KeySelector new_key_selector;
	HMAC_SHA256_CTX hmac;
	BIGNUM *max = BN_new();
	BIGNUM *e = NULL;
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *r0 = BN_new();
	BIGNUM *r1 = BN_new();

	if (bit_length <= 0) {
		fprintf(stderr,"MSECRET_Extract_Prime_BN: Invalid bit length (%d)\n", bit_length);
		// TODO: Change this to return an error at some point.
		abort();
	}

	if ((flags & ~kSupportedFlags) != 0) {
		fprintf(stderr,"MSECRET_Extract_Prime_BN: Unexpected flags\n");
		// TODO: Change this to return an error at some point.
		abort();
	}

	HMAC_SHA256_Init(&hmac);
	HMAC_SHA256_UpdateKey(&hmac, key_selector, sizeof(MSECRET_KeySelector));
	HMAC_SHA256_EndKey(&hmac);
	HMAC_SHA256_StartMessage(&hmac);
	HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"Prime:", 6);

	if (flags & MSECRET_PRIME_STD_EXPONENT) {
		e = BN_new();
		BN_set_word(e, RSA_F4);
		HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"GCD65537=0:", 11);
	}

#if MSECRET_PRIME_LEELIM
	if (flags & MSECRET_PRIME_LEELIM) {
		HMAC_SHA256_UpdateMessage(&hmac, (const uint8_t*)"LeeLim:", 7);
	}
#endif

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
			abort();
		}
#endif

		if (e != NULL) {
			BN_sub(r0, prime, BN_value_one());
			BN_gcd(r1, r0, e, ctx);
			if (!BN_is_one(r1)) {
				// TODO: Calculate how often this really happens...
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

#if 0
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

	if (mod_length <= 0) {
		fprintf(stderr, "MSECRET_Extract_RSA_X931: Invalid mod length (%d)\n", mod_length);
		// TODO: Change this to return an error at some point.
		abort();
	}

	bitsp = (mod_length + 1) / 2;
	bitsq = mod_length - bitsp;

	if (rsa->e == NULL) {
		rsa->e = BN_new();
		BN_set_word(rsa->e, RSA_F4);
	}

	BN_set_bit(max101, 102);
	BN_sub_word(max101, 1);

	BN_set_bit(max, bitsp);
	BN_sub_word(max, 1);

	for (i = 0; i < 3; i++) {
		char sel_str[] = "Xp0";

		// Mutate the above string to "Xp1", "Xp2"...
		sel_str[2] += i;

		MSECRET_CalcKeySelector(
			new_key_selector,
			key_selector, sizeof(MSECRET_KeySelector),
			sel_str, 0
		);

		MSECRET_Extract_Integer_BN(
			xp[i],
			(i == 0)
				? max
				: max101,
			new_key_selector,
			ikm, ikm_size
		);
	}

	BN_set_bit(xp[0], 0);
	BN_set_bit(xp[0], bitsp - 1);
	BN_set_bit(xp[0], bitsp - 2);

	BN_zero(max);
	BN_set_bit(max, bitsq);
	BN_sub_word(max, 1);

	for (i = 0; i < 3; i++) {
		char sel_str[] = "Xq0";

		// Mutate the above string to "Xq1", "Xq2"...
		sel_str[2] += i;

		MSECRET_CalcKeySelector(
			new_key_selector,
			key_selector, sizeof(MSECRET_KeySelector),
			sel_str, 0
		);

		MSECRET_Extract_Integer_BN(
			xq[i],
			(i == 0)
				? max
				: max101,
			new_key_selector,
			ikm, ikm_size
		);
	}

	BN_set_bit(xq[0], 0);
	BN_set_bit(xq[0], bitsq - 1);
	BN_set_bit(xq[0], bitsq - 2);

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
#endif


void
MSECRET_Extract_RSA(
	RSA *rsa,
	int mod_length,
	int flags,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	static const int kSupportedFlags = 0;
	// TODO: Review http://www.opensource.apple.com/source/OpenSSL097/OpenSSL097-16/openssl/crypto/rsa/rsa_gen.c
	uint32_t mod_length_be = htonl(mod_length);
	MSECRET_KeySelector prime_key_selector;
	int bitsp, bitsq;
	HMAC_SHA256_CTX hmac;
	BN_CTX *ctx = BN_CTX_new();

	if ((flags & ~kSupportedFlags) != 0) {
		fprintf(stderr,"MSECRET_Extract_RSA: Unexpected flags\n");
		// TODO: Change this to return an error at some point.
		abort();
	}

	if (mod_length <= 0) {
		fprintf(stderr,"MSECRET_Extract_RSA: Invalid mod length (%d)\n", mod_length);
		// TODO: Change this to return an error at some point.
		abort();
	}

	bitsp = (mod_length + 1) / 2;
	bitsq = mod_length - bitsp;

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
		prime_key_selector,
		key_selector, sizeof(MSECRET_KeySelector),
		"RSA:a", 5
	);

	MSECRET_Extract_Prime_BN(
		rsa->p,
		bitsp,
		flags | MSECRET_PRIME_STD_EXPONENT,
		prime_key_selector,
		ikm, ikm_size
	);

	MSECRET_CalcKeySelector(
		prime_key_selector,
		key_selector, sizeof(MSECRET_KeySelector),
		"RSA:b", 5
	);

	MSECRET_Extract_Prime_BN(
		rsa->q,
		bitsq,
		flags | MSECRET_PRIME_STD_EXPONENT,
		prime_key_selector,
		ikm, ikm_size
	);

	assert(BN_cmp(rsa->p, rsa->q) != 0);

	// P should be the larger of the two, by convention.
	if (BN_cmp(rsa->p, rsa->q) < 0)
	{
		BIGNUM *tmp=rsa->p;
		rsa->p=rsa->q;
		rsa->q=tmp;
	}

#if 0
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
#else
	BIGNUM *r0 = BN_CTX_get(ctx);
	BIGNUM *r1 = BN_CTX_get(ctx);
	BIGNUM *r2 = BN_CTX_get(ctx);
	BIGNUM *r3 = BN_CTX_get(ctx);

	if (rsa->n == NULL) {
		rsa->n = BN_new();
	}

	if (rsa->d == NULL) {
		rsa->d = BN_new();
	}

	// Calculate N
	BN_mul(rsa->n, rsa->p, rsa->q, ctx);

	// Calculate D
	BN_sub(r0, rsa->n, rsa->p);
	BN_sub(r1, r0, rsa->q);
	BN_add(r0, r1, BN_value_one());
	BN_mod_inverse(rsa->d, rsa->e, r0, ctx);

	// Calculate DMP1
	if (rsa->dmp1 == NULL) {
		rsa->dmp1 = BN_new();
	}
	BN_sub(r1, rsa->p, BN_value_one());
	BN_mod(rsa->dmp1,rsa->d,r1,ctx);

	// Calculate DMQ1
	if (rsa->dmq1 == NULL) {
		rsa->dmq1 = BN_new();
	}
	BN_sub(r2, rsa->q, BN_value_one());
	BN_mod(rsa->dmq1,rsa->d,r2,ctx);

	// Calculate IQMP
	if (rsa->iqmp == NULL) {
		rsa->iqmp = BN_new();
	}
	BN_mod_inverse(rsa->iqmp,rsa->q,rsa->p,ctx);

#endif

	BN_CTX_free(ctx);
}

void MSECRET_Extract_EC_KEY(
	EC_KEY *ec_key_out,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
) {
	BN_CTX *ctx = BN_CTX_new();
	const EC_GROUP *group = EC_KEY_get0_group(ec_key_out);
	BIGNUM *order = BN_CTX_get(ctx);
	BIGNUM *privateKey = BN_CTX_get(ctx);
	MSECRET_KeySelector new_key_selector;
	EC_POINT *ec_pub_key = NULL;

	if (group == NULL) {
		fprintf(stderr,"MSECRET_Extract_EC_KEY: No group specified\n");
		// TODO: Change this to return an error at some point.
		abort();
	}

	if (!EC_GROUP_get_order(group, order, ctx)) {
		fprintf(stderr,"MSECRET_Extract_EC_KEY: Unable to extract order\n");
		// TODO: Change this to return an error at some point.
		abort();
	}

	// TODO: Derive a new selector based on the group...?
	memcpy(new_key_selector, key_selector, sizeof(MSECRET_KeySelector));

	MSECRET_Extract_Integer_BN(
		privateKey,
		order,
		new_key_selector,
		ikm, ikm_size
	);

	EC_KEY_set_private_key(ec_key_out, privateKey);

	ec_pub_key = EC_POINT_new(group);
	if (!EC_POINT_mul(group, ec_pub_key, privateKey, NULL, NULL, NULL)) {
		fprintf(stderr,"Error at EC_POINT_mul.\n");
		// TODO: Change this to return an error at some point.
		abort();
	}

	EC_KEY_set_public_key(ec_key_out, ec_pub_key);

	if (!EC_KEY_check_key(ec_key_out)) {
		fprintf(stderr,"Error at EC_KEY_check_key.\n");
		// TODO: Change this to return an error at some point.
		abort();
	}

	EC_POINT_free(ec_pub_key);
	BN_CTX_free(ctx);
}

#if MSECRET_UNIT_TEST

int
hex_dump(FILE* file, const uint8_t *data, size_t data_len)
{
	int ret = 0;
	while (data_len > 0) {
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
