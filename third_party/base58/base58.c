/* Converted to C by Rusty Russell, based on bitcoin source: */
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "base58.h"
#include <assert.h>
#include <openssl/bn.h>
//#include <openssl/obj_mac.h>
//#include <openssl/sha.h>
#include <string.h>
#include <ctype.h>

static const char enc_16[] = "0123456789abcdef";
static const char enc_58[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static char encode_char(unsigned long val, const char *enc)
{
	assert(val < strlen(enc));
	return enc[val];
}

static int decode_char(char c, const char *enc)
{
	const char *pos = strchr(enc, c);
	if (!pos)
		return -1;
	return pos - enc;
}

/*
 * Encode a byte sequence as a base58-encoded string.  This is a bit
 * weird: returns pointer into buf (or NULL if wouldn't fit).
 */
char *encode_base58(char *buf, size_t buflen,
			   const uint8_t *data, size_t data_len)
{
	char *p;
	BIGNUM bn;

	/* Convert to a bignum. */
	BN_init(&bn);
	BN_bin2bn(data, data_len, &bn);

	/* Add NUL terminator */
	if (!buflen) {
		p = NULL;
		goto out;
	}
	p = buf + buflen;
	*(--p) = '\0';

	/* Fill from the back, using a series of divides. */
	while (!BN_is_zero(&bn)) {
		int rem = BN_div_word(&bn, 58);
		if (--p < buf) {
			p = NULL;
			goto out;
		}
		*p = encode_char(rem, enc_58);
	}

	/* Now, this is really weird.  We pad with zeroes, but not at
	 * base 58, but in terms of zero bytes.  This means that some
	 * encodings are shorter than others! */
	while (data_len && *data == '\0') {
		if (--p < buf) {
			p = NULL;
			goto out;
		}
		*p = encode_char(0, enc_58);
		data_len--;
		data++;
	}

out:
	BN_free(&bn);
	return p;
}

/*
 * Decode a base_n-encoded string into a byte sequence.
 */
bool raw_decode_base_n(BIGNUM *bn, const char *src, size_t len, int base)
{
	const char *enc;

	BN_zero(bn);

	assert(base == 16 || base == 58);
	switch (base) {
	case 16:
		enc = enc_16;
		break;
	case 58:
		enc = enc_58;
		break;
	}

	while (len) {
		char current = *src;

		if (base == 16)
			current = tolower(current);	/* TODO: Not in ccan. */
		int val = decode_char(current, enc);
		if (val < 0) {
			BN_free(bn);
			return false;
		}
		BN_mul_word(bn, base);
		BN_add_word(bn, val);
		src++;
		len--;
	}

	return true;
}

/*
 * Decode a base58-encoded string into a byte sequence.
 */
bool raw_decode_base58(BIGNUM *bn, const char *src, size_t len)
{
	return raw_decode_base_n(bn, src, len, 58);
}
