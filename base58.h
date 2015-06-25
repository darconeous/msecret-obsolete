#ifndef BASE58_H
#define BASE58_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Encode a byte sequence as a base58-encoded string.  This is a bit
 * weird: returns pointer into buf (or NULL if wouldn't fit).
 */
char *encode_base58(char *buf, size_t buflen,
			   const uint8_t *data, size_t data_len);

#endif /* PETTYCOIN_BASE58_H */
