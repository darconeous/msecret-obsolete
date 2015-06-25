

CFLAGS=-g -O0  -Wno-deprecated-declarations

LDFLAGS=-lcrypto

all: msecret ecollect

msecret: main.o lkdf.o msecret.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o help.o base58.o
ecollect: ecollect.o hmac_sha/sha2.o

test: lkdf-test msecret-test
	./lkdf-test

lkdf-test: lkdf-test.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o
msecret-test: lkdf.o msecret-test.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o


msecret-test.o: msecret.c
	$(CC) -c -DMSECRET_UNIT_TEST=1 msecret.c -o msecret-test.o

lkdf-test.o: lkdf.c
	$(CC) -c -DLKDF_UNIT_TEST=1 lkdf.c -o lkdf-test.o

clean:
	$(RM) *.o hmac_sha/*.o msecret-test lkdf-test ecollect msecret
