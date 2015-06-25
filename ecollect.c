
#include "hmac_sha/sha2.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

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
add_entropy(uint8_t* pool, int pool_len, const uint8_t* entropy, int entropy_len)
{
	int i;
	SHA256_CTX hash;
	uint8_t hashval[SHA256_DIGEST_LENGTH];

	while (entropy_len > pool_len) {
		add_entropy(pool, pool_len, entropy, pool_len);
		entropy += pool_len;
		entropy_len -= pool_len;
	}

	if (entropy_len <= 0) {
		// Nothing to do.
		return;
	}

	// Step 1: XOR in the entropy, repeating if necessary.
	for (i = 0; (entropy_len > 0) && (i <= (pool_len-1)/entropy_len); i++) {
		int offset = i*entropy_len;
		int len = entropy_len;
		if (offset+len > pool_len) {
			len = pool_len - offset;
		}
		if (len < 0) {
			break;
		}
		xorcpy(pool+offset, entropy, len);
	}

	// Step 2: Mix it up.
	if (pool_len < SHA256_DIGEST_LENGTH) {
		SHA256_Init(&hash);
		SHA256_Update(&hash, pool, pool_len);
		SHA256_Final(hashval, &hash);
		memcpy(pool, hashval, pool_len);
	} else {
		SHA256_Init(&hash);
		SHA256_Update(&hash, pool+pool_len-SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
		SHA256_Update(&hash, pool, SHA256_DIGEST_LENGTH);
		SHA256_Final(hashval, &hash);
		memcpy(pool, hashval, SHA256_DIGEST_LENGTH);

		for (i = 0; i < pool_len/SHA256_DIGEST_LENGTH; i++) {
			int offset = i*SHA256_DIGEST_LENGTH;
			int len = SHA256_DIGEST_LENGTH*2;

			if (offset+len > pool_len) {
				len = pool_len - offset;
			}

			if (len < SHA256_DIGEST_LENGTH) {
				break;
			}

			SHA256_Init(&hash);
			SHA256_Update(&hash, pool+offset, len);
			SHA256_Final(hashval, &hash);
			memcpy(pool+offset+SHA256_DIGEST_LENGTH, hashval, len-SHA256_DIGEST_LENGTH);
		}
	}
}

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
			i = fprintf(file,"%02X",*data);
		} else {
			i = fprintf(file, "%02X%s",*data, sep);
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

static int gInterrupted;
static void
signal_handler(int sig) {
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

	while (!feof(stdin) && !ferror(stdin) && !gInterrupted) {
		uint8_t buffer[1024*20] = {};
		int len;
		len = fread(
			buffer,
			1,
			epool_size > sizeof(buffer)
				? sizeof(buffer)
				: epool_size,
			stdin
		);

		if (len < 0) {
			perror("fread");
			exit(EXIT_FAILURE);
		}

		add_entropy(epool, epool_size, buffer, len);
		bytes_consumed += len;
	}

	fprintf(stderr, "done. Consumed %lld bytes\n", (long long)bytes_consumed);
//	hex_dump(stderr, epool, epool_size, "");
	fprintf(stderr, "\n");
	return EXIT_SUCCESS;
}
