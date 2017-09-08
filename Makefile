

CFLAGS = -g -O0 -Wno-deprecated-declarations

LDFLAGS = -lcrypto

#OPENSSL_PATH = /usr
OPENSSL_PATH = $(HOME)/homebrew/opt/openssl

CFLAGS += -I$(OPENSSL_PATH)/include
LDFLAGS += -L$(OPENSSL_PATH)/lib

all : msecret ecollect

test : lkdf-test msecret-test
	./lkdf-test
	./msecret-test

msecret : main.o lkdf.o msecret.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o help.o base58.o base32.o
ecollect : ecollect.o hmac_sha/sha2.o

lkdf-test : CFLAGS += -DLKDF_UNIT_TEST=1
lkdf-test: lkdf-test.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o

lkdf-test.o : lkdf.c
	$(CC) -c $(CFLAGS) lkdf.c -o lkdf-test.o

msecret-test : CFLAGS += -DMSECRET_UNIT_TEST=1
msecret-test : lkdf.o msecret-test.o lkdf.o hmac_sha/hmac_sha256.o hmac_sha/sha2.o

msecret-test.o : msecret.c
	$(CC) -c $(CFLAGS) msecret.c -o msecret-test.o

clean:
	$(RM) *.o hmac_sha/*.o msecret-test lkdf-test ecollect msecret
