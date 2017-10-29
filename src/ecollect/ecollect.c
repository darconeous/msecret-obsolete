/**
 * Entropy Collection Tool
 *
 * Copyright (C) 2017 Robert Quattlebaum, All Rights Reserved.
 *
 * # Abstract #
 *
 * This tool collects entropy from an input stream into a fixed-length
 * file that can later be used directly as keying material. It allows you
 * to cherry-pick the entropy sources you use for key generation rather
 * than relying on operating system methods. Its results are reproducable
 * given the same input, but this behavior is only guaranteed when using
 * the same version of the tool. The tool may be invoked multiple times
 * to pull entropy from multiple different sources. You may also pull
 * entropy from device files like `/dev/urandom`, pressing CTRL-C once
 * you feel you have collected enough entropy.
 *
 * # Usage #
 *
 * You must start with a file that is the size you want your keying
 * material to be. This is easily accomplished using `dd`:
 *
 *     dd if=/dev/zero of=secret.bin bs=1 count=64
 *
 * You can then use ecollect to gather up entropy into that file:
 *
 *     # Collect entropy from microphone. (Press CTRL-C to stop)
 *     arecord | ./ecollect secret.bin
 *
 *     # Collect entropy from /dev/urandom. (Press CTRL-C to stop)
 *     ./ecollect secret.bin /dev/urandom
 *
 * # More Information #
 *
 * See README.md for more information.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

#include "hmac_sha/sha2.h"
#include "hmac_sha/hmac_sha256.h"

//#define DEBUG 1

int
hex_dump(FILE* file, const uint8_t *data, size_t data_len, const char* sep)
{
	int ret = 0;
	if (sep == NULL) {
		sep = " ";
	}
	while(data_len > 0) {
		int i = 0;
		if (data_len == 1) {
			i = fprintf(file,"%02X", *data);
		} else {
			i = fprintf(file, "%02X%s", *data, sep);
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

static void *
xorcpy(void *restrict dst, const void *restrict src, size_t n)
{
	uint8_t* idx = (uint8_t*)dst;
	for (; n != 0 ; n--) {
		*idx++ ^= *(const uint8_t*)src++;
	}
	return dst;
}

static void
mix_pool(uint8_t* pool, const int pool_len)
{
	uint8_t hashval[SHA512_DIGEST_LENGTH];

#if DEBUG
	fprintf(stderr, "pool-in:  ");
	hex_dump(stderr, pool, pool_len, "");
	fprintf(stderr, "\n");
#endif

	if (pool_len <= SHA256_DIGEST_LENGTH) {
		// Pool is small enough that we can just hash it once
		// with SHA256 and be done with it.

		SHA256_CTX hash;

		SHA256_Init(&hash);
		SHA256_Update(&hash, pool, pool_len);
		SHA256_Final(hashval, &hash);

		memcpy(pool, hashval, pool_len);

	} else if (pool_len <= SHA512_DIGEST_LENGTH) {
		// Pool is small enough that we can just hash it once
		// with SHA512 and be done with it.

		SHA512_CTX hash;

		SHA512_Init(&hash);
		SHA512_Update(&hash, pool, pool_len);
		SHA512_Final(hashval, &hash);

		memcpy(pool, hashval, pool_len);


	} else {
		// Pool is larger than the digest length, so we need to use a
		// slightly more complicated algorithm to mix up the pool.
		// The idea is to break up the pool into `n` digest-length-sized
		// blocks and calculate the HMAC-SHA256 of each one, using the
		// previous pool as the key. We also chain the HMAC operations
		// by prepending the previous HMAC result to the message(using
		// digest of all zeros for the initial block). This preserves
		// the total amount of entropy present in the system while
		// ensuring that there are no correlations in output.

		int i, j;
		HMAC_SHA256_CTX hmac;

		// Initialize hashval to all zeros. This gets updated
		// per iteration for feedback into the next step.
		memset(hashval, 0, sizeof(hashval));

		// Multiple rounds are used to ensure that the entropy
		// is well distributed across the pool. Note that
		// this is only used for pool sizes larger than 64
		// bytes (512 bits): in the smaller cases we end up
		// just using SHA-256 or SHA-512 directly.
		// Number of rounds depends on how large the pool is.
		for (j = 0; j < (pool_len + SHA256_DIGEST_LENGTH/2) / SHA256_DIGEST_LENGTH; j++) {
			// We use the entire state of the pool as our key.
			// This helps us ensure that as much entropy as
			// possible is mixed across the rounds.
			HMAC_SHA256_Init(&hmac);
			HMAC_SHA256_UpdateKey(&hmac, pool, pool_len);
			HMAC_SHA256_EndKey(&hmac);

			for (i = 0; i < (pool_len + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH; i++) {
				int offset = i * SHA256_DIGEST_LENGTH;
				int len = SHA256_DIGEST_LENGTH;

				if (offset + len > pool_len) {
					len = pool_len - offset;
				}

				HMAC_SHA256_StartMessage(&hmac);
				// Feedback from previous iteration.
				HMAC_SHA256_UpdateMessage(&hmac, hashval, SHA256_DIGEST_LENGTH);
				// Add the next digest-sized block from the pool.
				HMAC_SHA256_UpdateMessage(&hmac, pool + offset, len);
				HMAC_SHA256_EndMessage(hashval, &hmac);

				memcpy(pool + offset, hashval, len);
			}
		}
	}

#if DEBUG
	fprintf(stderr, "pool-out: ");
	hex_dump(stderr, pool, pool_len, "");
	fprintf(stderr, "\n");
#endif
}

static void
add_entropy(uint8_t* pool, int pool_len, const uint8_t* entropy, int entropy_len)
{
	// Break up entropy into pool-sized blocks.
	// We should never execute the code in this loop
	// because the only place where this method is called
	// ensures that it is never called with an entropy_len
	// that is larger than pool_len. Nonetheless, this code
	// is being left in for robustness purposes.
	while (entropy_len > pool_len) {
		add_entropy(pool, pool_len, entropy, pool_len);
		entropy += pool_len;
		entropy_len -= pool_len;
	}

	// If there is no more entropy, we are done.
	if (entropy_len <= 0) {
		return;
	}

#if DEBUG
	fprintf(stderr, "entropy:  ");
	hex_dump(stderr, entropy, entropy_len, "");
	fprintf(stderr, "\n");
#endif

	// Step 1: XOR in the entropy.
	xorcpy(pool, entropy, entropy_len);

	// Step 2: Mix up the pool.
	mix_pool(pool, pool_len);

	// Step 3: XOR in the entropy again. This helps frustrate active attacks.
	xorcpy(pool, entropy, entropy_len);
}

static int gInterrupted;

static void
signal_handler(int sig)
{
	gInterrupted = 1;
	fprintf(stderr, "Caught signal %d\n", sig);
	signal(sig, NULL);
}

int
main(int argc, char * argv[])
{
	int fd = -1;
	uint8_t *epool = NULL;
	int epool_size = 0;
	size_t bytes_consumed = 0;
	uint8_t *buffer;
	int buffer_len = 0;

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);

	if (argc < 2) {
		fprintf(stderr,"syntax: %s <pool-file> [input-file]\n",argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDWR);

	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	epool_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	epool = mmap(NULL, epool_size, PROT_READ|PROT_WRITE,MAP_FILE|MAP_SHARED,fd, 0);

	if ((epool == NULL) || (epool == MAP_FAILED)) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr,"mmapped %d bytes of %s\n",epool_size,argv[1]);

	if (argc >= 3) {
		stdin = fopen(argv[2], "r");
		fprintf(stderr,"opened %s\n",argv[2]);
	}

	buffer = malloc(epool_size);

	while (!feof(stdin) && !ferror(stdin) && !gInterrupted) {
		int len = fread(
			buffer + buffer_len,
			1,
			epool_size - buffer_len,
			stdin
		);

		if (len < 0) {
			perror("fread");

			// Dump the rest of the buffer into the entropy pool.
			add_entropy(epool, epool_size, buffer, buffer_len);
			bytes_consumed += buffer_len;

			exit(EXIT_FAILURE);
		}

		buffer_len += len;

		if (buffer_len == epool_size) {
			// Empty the buffer into the entropy pool.

			add_entropy(epool, epool_size, buffer, buffer_len);
			bytes_consumed += buffer_len;
			buffer_len = 0;
		}
	}

	// Dump the rest of the buffer into the entropy pool.
	add_entropy(epool, epool_size, buffer, buffer_len);
	bytes_consumed += buffer_len;

	fprintf(stderr, "done. Consumed %lld bytes\n", (long long)bytes_consumed);

#if DEBUG
	hex_dump(stderr, epool, epool_size, "");
#endif

	fprintf(stderr, "\n");

	free(buffer);

	return EXIT_SUCCESS;
}
