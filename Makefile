


gcc -DMSECRET_UNIT_TEST=1 lkdf.c hmac_sha/hmac_sha256.c hmac_sha/sha2.c msecret.c -o msecret && ./msecret

msecret: main.o lkdf.o msecret.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o help.o

test: lkdf-test msecret-test
	./lkdf-test

lkdf-test: lkdf-test.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o
msecret-test: lkdf.o msecret-test.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o


msecret-test.o: msecret.c
	$(CC) -c -DMSECRET_UNIT_TEST=1 msecret.c -o msecret-test.o

lkdf-test.o: lkdf.c
	$(CC) -c -DLKDF_UNIT_TEST=1 lkdf.c -o lkdf-test.o

clean:
	$(RM) *.o hmac_sha/*.o msecret-test lkdf-test
