


gcc -DMSECRET_UNIT_TEST=1 lkdf.c hmac_sha/hmac_sha256.c hmac_sha/sha2.c msecret.c -o msecret && ./msecret

msecret-test.o: msecret.c
	$(CC) -c -DMSECRET_UNIT_TEST=1 msecret.c -o msecret-test.o

lkdf-test.o: lkdf.c
	$(CC) -c -DLKDF_UNIT_TEST=1 lkdf.c -o lkdf-test.o

lkdf-test: lkdf-test.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o
msecret-test: lkdf.o msecret-test.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o
