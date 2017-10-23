


#ifndef __MSECRET_H__
#define __MSECRET_H__ 1

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "lkdf.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

typedef LKDF_SHA256_KeySelector MSECRET_KeySelector;

#define kMSECRET_OK        0
#define kMSECRET_FAILED    1

void MSECRET_CalcKeySelector(
	MSECRET_KeySelector keySelector_out,
	const uint8_t *salt, size_t salt_size,
	const char *info, size_t info_size
);

void MSECRET_Extract_Bytes(
	uint8_t *key_out, size_t key_size,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
);

void MSECRET_Extract_Integer(
	uint8_t *val,
	const uint8_t *maxval, size_t maxval_size,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
);

void MSECRET_Extract_Integer_BN(
	BIGNUM *val,
	const BIGNUM *max,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
);

int MSECRET_Extract_Prime_BN(
	BIGNUM *prime,
	int bit_length,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
);

int MSECRET_Extract_RSA(
	RSA *rsa,
	int mod_length,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
);

/* Note: group must already be set on EC_KEY */
int MSECRET_Extract_EC_KEY(
	EC_KEY *ec_key_out,
	const MSECRET_KeySelector key_selector,
	const uint8_t *ikm, size_t ikm_size
);

#endif
