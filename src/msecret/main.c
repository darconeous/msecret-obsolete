
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "help.h"
#include <sys/errno.h>
#include <inttypes.h>

#include "hmac_sha/sha2.h"

#include <libmsecret/msecret.h>
#include <libmsecret/lkdf.h>

#define HEADER_SHA_H 1
#define SHA_DIGEST_LENGTH (160/8)

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include "base58/base58.h"
#include "base32/base32.h"

#define MASTER_SECRET_BLOCK_SIZE (1024*4)

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

void
print_version()
{
	printf("msecret v0.0\n");
}

static arg_list_item_t option_list[] = {
	{ 'h', "help",	NULL, "Print Help"				},
	{ 'v', "version", NULL, "Print Version Information" },
	{ 'd', "debug", NULL, "Enable debugging mode"	},
	{ 'i', "input",	NULL, "Input file (use '-' for stdin)"				},
	{ 'o', "output",	NULL, "Output file (stdout is default)"				},
	{ 'k', "key-identifier",	"KID", "Key identifier (default is empty string)"				},
	{ 0, "key-max",	"n", "Maximum numerical value for output key"				},
	{ 'l', "key-length",	"bytes", "output key length, in bytes"				},
	{   0, "format-bin",	NULL, "Output raw binary key"				},
	{   0, "format-hex",	NULL, "Output hexidecimal key"				},
	{   0, "format-dec",	NULL, "Output decimal key"				},
	{   0, "format-b58",	NULL, "Output Base58 key"				},
	{   0, "format-b32",	NULL, "Output Base32 key"				},
	{   0, "format-der",	NULL, "Output DER"				},
	{   0, "format-pem",	NULL, "Output PEM"				},
	{   0, "format-rsa",	NULL, "Output PEM (RSA)"				},
	{ 0, "dec-zero-fill", "X", "Zero fill key to X places"},
	{ 0, "integer",	NULL, "Derive a large integer (default)"				},
	{ 0, "prime",	NULL, "Derive a large prime"				},
	{ 0, "ec", "curve-name", "Derive a EC private key"				},
	{ 0, "rsa",	NULL, "Derive a RSA key"				},
	{ 0, "bitcoin",	NULL, "Derive a bitcoin address"				},
	{ 0, "list-curves", NULL, "Print out list of supported curves"				},
	{ 0, "private",	NULL, "Output private key"				},
	{ 0, "public",	NULL, "Output public key (default)"				},
	{ 0 }
};

int
main(int argc, char * argv[])
{
	int ret = 0;
	int i = 0;
	const char* master_secret_filename = NULL;
	FILE* master_secret_file = NULL;
	uint8_t *master_secret = NULL;
	size_t master_secret_len = 0;
	int debug_mode = 0;
	const char* key_identifier = NULL;
	ssize_t key_byte_length = -1;
	uint8_t* key_max = NULL;
	uint8_t* output_key = NULL;
	const char* output_key_filename = NULL;
	FILE* output_key_file = NULL;
	unsigned int zero_fill_digits = 0;
	MSECRET_KeySelector key_selector;
	enum {
		TYPE_BYTES,
		TYPE_INTEGER,
		TYPE_PRIME,
		TYPE_RSA,
		TYPE_EC,
		TYPE_DSA_PARAM,
		TYPE_BITCOIN,
	} secret_type;

	enum {
		OUTPUT_UNSPECIFIED,
		OUTPUT_RAW,
		OUTPUT_HEX,
		OUTPUT_DEC,
		OUTPUT_B64,
		OUTPUT_B32,
		OUTPUT_B58,
		OUTPUT_DER,
		OUTPUT_PEM,
		OUTPUT_PEM_RSA,
	} output_format = OUTPUT_UNSPECIFIED;
	RSA *rsa = NULL;
	EC_KEY *ec_key = NULL;
	EVP_PKEY* pkey = NULL;
	bool outputPrivateKey = false;

	secret_type = TYPE_BYTES;

	BEGIN_LONG_ARGUMENTS(ret)
	HANDLE_LONG_ARGUMENT("input")
	{
		master_secret_filename = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("output")
	{
		output_key_filename = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("format-dec")
	{
		output_format = OUTPUT_DEC;
	}
	HANDLE_LONG_ARGUMENT("format-b64")
	{
		output_format = OUTPUT_B64;
	}
	HANDLE_LONG_ARGUMENT("format-b32")
	{
		output_format = OUTPUT_B32;
	}
	HANDLE_LONG_ARGUMENT("format-b58")
	{
		output_format = OUTPUT_B58;
	}
	HANDLE_LONG_ARGUMENT("format-btc")
	{
		output_format = OUTPUT_B58;
	}
	HANDLE_LONG_ARGUMENT("format-b16")
	{
		output_format = OUTPUT_HEX;
	}
	HANDLE_LONG_ARGUMENT("format-hex")
	{
		output_format = OUTPUT_HEX;
	}
	HANDLE_LONG_ARGUMENT("format-bin")
	{
		output_format = OUTPUT_RAW;
	}
	HANDLE_LONG_ARGUMENT("format-raw")
	{
		output_format = OUTPUT_RAW;
	}
	HANDLE_LONG_ARGUMENT("format-bin")
	{
		output_format = OUTPUT_RAW;
	}
	HANDLE_LONG_ARGUMENT("format-pem")
	{
		output_format = OUTPUT_PEM;
	}
	HANDLE_LONG_ARGUMENT("format-der")
	{
		output_format = OUTPUT_DER;
	}
	HANDLE_LONG_ARGUMENT("format-pem-rsa")
	{
		output_format = OUTPUT_PEM_RSA;
	}
	HANDLE_LONG_ARGUMENT("format-rsa")
	{
		output_format = OUTPUT_PEM_RSA;
	}
	HANDLE_LONG_ARGUMENT("integer")
	{
		secret_type = TYPE_INTEGER;
	}
	HANDLE_LONG_ARGUMENT("prime")
	{
		secret_type = TYPE_PRIME;
	}
	HANDLE_LONG_ARGUMENT("private")
	{
		outputPrivateKey = true;
	}
	HANDLE_LONG_ARGUMENT("public")
	{
		outputPrivateKey = false;
	}
	HANDLE_LONG_ARGUMENT("bitcoin")
	{
		secret_type = TYPE_BITCOIN;
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_B58;
		}
		if (key_max != NULL) {
			fprintf(stderr, "You can't specify key-max with bitcoin keys\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		if (key_byte_length >= 0) {
			fprintf(stderr, "You can't specify key-length with bitcoin keys\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
		key_byte_length = 32;
	}
	HANDLE_LONG_ARGUMENT("ec")
	{
		const char* curve_name = argv[++i];
		int nid = OBJ_sn2nid(curve_name);
		if (nid == NID_undef) {
			nid = OBJ_ln2nid(curve_name);
		}
		if (nid == NID_undef) {
			nid = (int)strtol(curve_name, NULL, 0);
		}
		secret_type = TYPE_EC;
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_PEM;
		}
		if (ec_key != NULL) {
			fprintf(stderr, "Already specified a EC key type\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		ec_key = EC_KEY_new_by_curve_name(nid);
		if (ec_key == NULL) {
			fprintf(stderr, "Unknown curve named \"%s\"\n", curve_name);
			ret = EXIT_FAILURE;
			goto bail;
		}
		key_byte_length = 128; // Just set this to be big for now.
	}
	HANDLE_LONG_ARGUMENT("list-curves")
	{
		int i;
		/* Here we are just stupidly looping through every single
		 * NID value and seeing if we can successfully use
		 * EC_KEY_new_by_curve_name() on it. If we can, we get the
		 * short name and print it out. Kinda stupid, but a lot
		 * shorter than a "real" version.
		 */
		for (i = 1; i < 10000; i++) {
			ec_key = EC_KEY_new_by_curve_name(i);
			if (ec_key != NULL) {
				const char* sn = OBJ_nid2sn(i);
				const char* ln = OBJ_nid2ln(i);
				if (strcmp(sn, ln) == 0) {
					printf("%d\t%s\n", i, sn);
				} else {
					printf("%d\t%s\t%s\n", i, sn, ln);
				}
				EC_KEY_free(ec_key);
				ec_key = NULL;
			}
		}
		ret = EXIT_SUCCESS;
		goto bail;
	}
	HANDLE_LONG_ARGUMENT("rsa")
	{
		secret_type = TYPE_RSA;
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_PEM_RSA;
		}
		if (key_byte_length == -1) {
			// Default key length is 2048 bit.
			key_byte_length = 2048/8;
		}
	}
	HANDLE_LONG_ARGUMENT("key-identifier")
	{
		key_identifier = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("dec-zero-fill")
	{
		long val = strtol(argv[++i], NULL, 0);
		if (val < 0) {
			fprintf(stderr, "Cannot zero-fill negative zeros\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		zero_fill_digits = (unsigned int)val;
	}
	HANDLE_LONG_ARGUMENT("key-max")
	{
		secret_type = TYPE_INTEGER;
		if (key_max != NULL) {
			fprintf(stderr, "key-max already specified\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		if (key_byte_length >= 0) {
			fprintf(stderr, "key-byte-length already specified, you can't also specify key-max!\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		i++;
		if ((argv[i][0] == '0') && (argv[i][1] == 'x')) {
			// Hexidecimal maximum.
			fprintf(stderr, "Not yet implemented.\n");
			ret = EXIT_FAILURE;
			goto bail;
		} else {
			// Probabbly a decimal maximum.
			// Assume it fits within 32 bits for now.
			uint32_t max = (uint32_t)strtol(argv[i], NULL, 10);
			if (max == 0) {
				fprintf(stderr, "Bad maximum value of zero\n");
				ret = EXIT_FAILURE;
				goto bail;
			}
			key_max = calloc(sizeof(uint32_t), 1);
			if (key_max == NULL) {
				fprintf(stderr, "Malloc failure\n");
				ret = EXIT_FAILURE;
				goto bail;
			}
			if (max <= 0xFF) {
				key_max[0] = (max & 0xFF);
				key_byte_length = 1;
			} else if (max <= 0xFFFF) {
				key_max[0] = ((max & 0xFF00)>>8);
				key_max[1] = (max & 0xFF);
				key_byte_length = 2;
			} else if (max <= 0xFFFFFF) {
				key_max[0] = ((max & 0xFF0000)>>16);
				key_max[1] = ((max & 0xFF00)>>8);
				key_max[2] = (max & 0xFF);
				key_byte_length = 3;
			} else {
				key_max[0] = ((max & 0xFF000000)>>24);
				key_max[1] = ((max & 0xFF0000)>>16);
				key_max[2] = ((max & 0xFF00)>>8);
				key_max[3] = (max & 0xFF);
				key_byte_length = 4;
			}
		}
	}
	HANDLE_LONG_ARGUMENT("key-length")
	{
		if (key_max != NULL) {
			fprintf(stderr, "key-max already specified, you can't also specify key-length!\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		key_byte_length = (size_t)strtoll(argv[++i], NULL, 0);
	}
	HANDLE_LONG_ARGUMENT("debug") {
		debug_mode++;
	}
	HANDLE_LONG_ARGUMENT("version") {
		print_version();
		ret = 0;
		goto bail;
	}
	HANDLE_LONG_ARGUMENT("help") {
		print_version();
		print_arg_list_help(option_list,
			argv[0],"[args]");
		ret = EXIT_FAILURE;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(ret)
	HANDLE_SHORT_ARGUMENT('i')
	{
		master_secret_filename = argv[++i];
	}
	HANDLE_SHORT_ARGUMENT('l')
	{
		if (key_max != NULL) {
			fprintf(stderr, "key-max already specified, you can't also specify key-length!\n");
			ret = EXIT_FAILURE;
			goto bail;
		}
		key_byte_length = strtol(argv[++i], NULL, 0);
	}
	HANDLE_SHORT_ARGUMENT('o')
	{
		output_key_filename = argv[++i];
	}
	HANDLE_SHORT_ARGUMENT('k')
	{
		key_identifier = argv[++i];
	}

	HANDLE_SHORT_ARGUMENT('d') {
		debug_mode++;
	}
	HANDLE_SHORT_ARGUMENT('v') {
		print_version();
		ret = 0;
		goto bail;
	}
	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_version();
		print_arg_list_help(option_list,
			argv[0], "[args]");
		ret = EXIT_FAILURE;
		goto bail;
	}
	HANDLE_OTHER_ARGUMENT() {
		break;
	}
	END_ARGUMENTS

	if (master_secret_filename == NULL) {
		fprintf(stderr, "Filename of master secret not specified.\n");
		ret = EXIT_FAILURE;
		goto bail;
	}

	if (0 == strcmp(master_secret_filename, "-")) {
		master_secret_file = stdin;
	} else {
		master_secret_file = fopen(master_secret_filename, "r");
	}
	if (master_secret_file == NULL) {
		fprintf(stderr, "Unable to open master secret \"%s\"\n", master_secret_filename);
		ret = EXIT_FAILURE;
		goto bail;
	}

	master_secret = calloc(MASTER_SECRET_BLOCK_SIZE, 1);

	if (master_secret == NULL) {
		fprintf(stderr, "Ran out of memory loading \"%s\"\n", master_secret_filename);
		ret = EXIT_FAILURE;
		goto bail;
	}

	while(!feof(master_secret_file) && !ferror(master_secret_file)) {
		ssize_t read_bytes;
		read_bytes = fread(
			master_secret, 1, MASTER_SECRET_BLOCK_SIZE,
			master_secret_file
		);
		if (read_bytes < 0) {
			fprintf(stderr, "call to fread of \"%s\" failed: errno=%d\n", master_secret_filename, errno);
			ret = EXIT_FAILURE;
			goto bail;
		}
		master_secret_len += read_bytes;
		if (read_bytes == MASTER_SECRET_BLOCK_SIZE) {
			uint8_t *new_block;
			new_block = realloc(master_secret, master_secret_len+MASTER_SECRET_BLOCK_SIZE);
			if (new_block == NULL) {
				fprintf(stderr, "Ran out of memory loading \"%s\"\n", master_secret_filename);
				ret = EXIT_FAILURE;
				goto bail;
			}
			master_secret = new_block;
		}
	}

	if (key_byte_length == -1) {
		// Default key length is the same length of the master secret.
		key_byte_length = master_secret_len;
	}

	if (output_key_filename != NULL) {
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_RAW;
		}
		if (0 == strcmp(output_key_filename, "-")) {
			output_key_file = stdout;
		} else {
			output_key_file = fopen(output_key_filename, "w");
		}

		if (output_key_file == NULL) {
			fprintf(stderr, "Unable to open output key \"%s\" for writing\n", output_key_filename);
			ret = EXIT_FAILURE;
			goto bail;
		}
	} else {
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_HEX;
		}
		output_key_file = stdout;
	}

	output_key = calloc(key_byte_length+10, 1);

	if (output_key == NULL) {
		fprintf(stderr, "Ran out of memory for output key\n");
		ret = EXIT_FAILURE;
		goto bail;
	}

	MSECRET_CalcKeySelector(
		key_selector,
		NULL, 0,
		key_identifier, 0
	);

	if (key_max == NULL) {
		if (secret_type == TYPE_PRIME) {
			BIGNUM *prime = BN_new();
			MSECRET_Extract_Prime_BN(
				prime,
			    key_byte_length*8,
				0,
				key_selector,
				master_secret, master_secret_len
			);
			BN_bn2bin(prime, output_key);
			key_byte_length = BN_num_bytes(prime);
			BN_free(prime);
		} else if (secret_type == TYPE_RSA) {
			rsa = RSA_new();
			MSECRET_Extract_RSA(
				rsa,
			    key_byte_length*8,
				0,
				key_selector,
				master_secret, master_secret_len
			);
		} else if (secret_type == TYPE_BITCOIN
			|| secret_type == TYPE_EC
		) {
			MSECRET_Extract_EC_KEY(
				ec_key,
				key_selector,
				master_secret, master_secret_len
			);

		} else {
			// Extracts a random key with a length of
			// key_byte_length.
			MSECRET_Extract_Bytes(
				output_key, key_byte_length,
				key_selector,
				master_secret, master_secret_len
			);
		}
	} else {
		// Extracts a key that is less than or
		// equal to the specific value of key_max.
		MSECRET_Extract_Integer(
			output_key, key_max, key_byte_length,
			key_selector,
			master_secret, master_secret_len
		);
	}

	if (secret_type == TYPE_BITCOIN) {
		if (outputPrivateKey) {
			uint8_t tmp[SHA256_DIGEST_LENGTH];
			EVP_MD_CTX md_ctx;

			const BIGNUM* ec_private_key;
			ec_private_key = EC_KEY_get0_private_key(ec_key);
			assert(output_key != NULL);
			assert(key_byte_length >= 32);
			BN_bn2bin(ec_private_key, output_key);
			key_byte_length = 32;

			EVP_MD_CTX_init(&md_ctx);
			SHA256_Data(output_key, key_byte_length, (char*)&tmp);
			SHA256_Data(tmp, SHA256_DIGEST_LENGTH, (char*)tmp);

			output_key = realloc(output_key, key_byte_length+6);
			memmove(output_key+1, output_key, key_byte_length);

			output_key[0] = 0x80;
			key_byte_length += 1;

			EVP_DigestInit(&md_ctx, EVP_sha256());
			EVP_DigestUpdate(&md_ctx,output_key,key_byte_length);
			EVP_DigestFinal(&md_ctx,tmp,NULL);
			EVP_DigestInit(&md_ctx, EVP_sha256());
			EVP_DigestUpdate(&md_ctx,tmp,SHA256_DIGEST_LENGTH);
			EVP_DigestFinal(&md_ctx,tmp,NULL);

			EVP_MD_CTX_cleanup(&md_ctx);

			memcpy(output_key+key_byte_length, tmp, 4);

			key_byte_length += 4;
		} else {
			const EC_GROUP *group = NULL;
			const EC_POINT *ec_pub_key = NULL;
			uint8_t byte_x[32], byte_y[32];
			EVP_MD_CTX md_ctx;
			char hdr = 0x04;
			uint8_t tmp[SHA256_DIGEST_LENGTH];
			BIGNUM bn_key;
			BIGNUM bn_x, bn_y;

			group = EC_KEY_get0_group(ec_key);

			BN_init(&bn_key);
			BN_init(&bn_x);
			BN_init(&bn_y);

			ec_pub_key = EC_KEY_get0_public_key(ec_key);

			EC_POINT_get_affine_coordinates_GFp(group, ec_pub_key, &bn_x, &bn_y, NULL);

			BN_bn2bin(&bn_x, byte_x);
			BN_bn2bin(&bn_y, byte_y);

			EVP_MD_CTX_init(&md_ctx);
			EVP_DigestInit(&md_ctx, EVP_sha256());
			EVP_DigestUpdate(&md_ctx,&hdr,1);
			EVP_DigestUpdate(&md_ctx,byte_x,sizeof(byte_x));
			EVP_DigestUpdate(&md_ctx,byte_y,sizeof(byte_y));
			EVP_DigestFinal(&md_ctx,tmp,NULL);

			EVP_DigestInit(&md_ctx, EVP_ripemd160());
			EVP_DigestUpdate(&md_ctx,tmp,SHA256_DIGEST_LENGTH);
			EVP_DigestFinal(&md_ctx,output_key+1,NULL);

			output_key[0] = 0x00;
			key_byte_length = 21;

			EVP_DigestInit(&md_ctx, EVP_sha256());
			EVP_DigestUpdate(&md_ctx,output_key,key_byte_length);
			EVP_DigestFinal(&md_ctx,tmp,NULL);
			EVP_DigestInit(&md_ctx, EVP_sha256());
			EVP_DigestUpdate(&md_ctx,tmp,SHA256_DIGEST_LENGTH);
			EVP_DigestFinal(&md_ctx,tmp,NULL);

			EVP_MD_CTX_cleanup(&md_ctx);

			memcpy(output_key+key_byte_length, tmp, 4);

			key_byte_length +=4;
		}
		switch (output_format) {
		case OUTPUT_UNSPECIFIED:
			output_format = OUTPUT_B58;
			break;
		default:
			break;
		}
		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(pkey, ec_key);
	}

	if (secret_type == TYPE_RSA) {
		if(debug_mode)RSA_print_fp(stderr, rsa, 0);
		switch (output_format) {
		case OUTPUT_RAW:
		case OUTPUT_DER:
			if (outputPrivateKey) {
				i2d_RSAPrivateKey_fp(output_key_file,rsa);
			} else {
				i2d_RSAPublicKey_fp(output_key_file,rsa);
			}
			goto bail;
			break;
		case OUTPUT_B64:
		case OUTPUT_UNSPECIFIED:
			output_format = OUTPUT_PEM_RSA;
			break;
		default:
			break;
		}
		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_RSA(pkey, rsa);

		// TODO: Output just the mod?
		key_byte_length = 0;
	}

	if (secret_type == TYPE_EC) {
		switch (output_format) {
		case OUTPUT_DER:
			if (outputPrivateKey) {
				i2d_ECPrivateKey_fp(output_key_file, ec_key);
			} else {
				i2d_EC_PUBKEY_fp(output_key_file, ec_key);
			}
			goto bail;
			break;
		case OUTPUT_UNSPECIFIED:
			output_format = OUTPUT_PEM;
			break;
		default:
			break;
		}

		if (outputPrivateKey) {
			const BIGNUM* ec_private_key;
			ec_private_key = EC_KEY_get0_private_key(ec_key);
			assert(output_key != NULL);
			assert(key_byte_length >= BN_num_bytes(ec_private_key));
			BN_bn2bin(ec_private_key, output_key);
			key_byte_length = BN_num_bytes(ec_private_key);
		} else {
			// TODO: Output single point public key?
			key_byte_length = 0;
		}

		pkey = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(pkey, ec_key);
	}

	{
		switch (output_format) {
		case OUTPUT_DEC:
			{
				if (key_byte_length <= 4) {
					uint32_t v = 0;
					char* format_string = NULL;
					memcpy(((uint8_t*)&v)+4-key_byte_length, output_key, key_byte_length);
					v = htonl(v);
					asprintf(&format_string,"%%0%du\n", zero_fill_digits);
					if (format_string == NULL) {
						fprintf(stderr, "aprintf failed\n");
						ret = EXIT_FAILURE;
						goto bail;
					}
					fprintf(output_key_file, format_string, v);
					free(format_string);

#if 0
				} else if (key_byte_length <= 8) {
					uint64_t v = 0;
					memcpy(((uint8_t*)&v)+8-key_byte_length, output_key, key_byte_length);
					v = htonll(v);
					fprintf(output_key_file, "%llu\n", v);
#endif
				} else {
					fprintf(stderr, "Key size too large for decimal mode\n");
					ret = EXIT_FAILURE;
				}
			}
			break;
		case OUTPUT_HEX:
			hex_dump(output_key_file, output_key, key_byte_length, "");
			fprintf(output_key_file, "\n");
			break;
		case OUTPUT_B58:
			{
				char output_string[key_byte_length*5];
				output_string[0] = 0;

				fprintf(output_key_file, "%s\n", encode_base58(output_string, sizeof(output_string), output_key, key_byte_length));
			}
			break;
		case OUTPUT_B32:
			{
				char output_string[key_byte_length*8];
				output_string[0] = 0;

				base32_encode(output_key, key_byte_length, (unsigned char*)output_string);
				fprintf(output_key_file, "%s\n", output_string);
			}
			break;
		case OUTPUT_B64:
			fprintf(stderr, "Base64 output not yet implemented.\n");
			ret = EXIT_FAILURE;
			goto bail;
			break;
		case OUTPUT_RAW:
			{
				int written;
				written = fwrite(output_key,1,key_byte_length,output_key_file);
				if (written < 0) {
					fprintf(stderr, "Write failure: %d %s\n", errno, strerror(errno));
					ret = EXIT_FAILURE;
				} else {
					fprintf(stderr, "%d bytes written\n", written);
				}
			}
			break;
		case OUTPUT_PEM:
			if (pkey != NULL) {
				if (outputPrivateKey) {
					PEM_write_PrivateKey(
						output_key_file,
						pkey,
						NULL,
						NULL, 0, NULL, NULL
					);
				} else {
					PEM_write_PUBKEY(
						output_key_file,
						pkey
					);
				}
			} else {
				fprintf(stderr, "Bad output format\n");
				ret = EXIT_FAILURE;
				goto bail;
			}
			break;
		case OUTPUT_PEM_RSA:
			if (rsa != NULL) {
				if (outputPrivateKey) {
					PEM_write_RSAPrivateKey(
						output_key_file,
						rsa,
						NULL,
						NULL, 0, NULL, NULL
					);
				} else {
					PEM_write_RSAPublicKey(
						output_key_file,
						rsa
					);
				}
			} else {
				fprintf(stderr, "Bad output format\n");
				ret = EXIT_FAILURE;
				goto bail;
			}
			break;
		case OUTPUT_UNSPECIFIED:
		default:
			fprintf(stderr, "Unknown output format\n");
			ret = EXIT_FAILURE;
			goto bail;
			break;
		}
	}

bail:
	EVP_PKEY_free(pkey);

	if (output_key != NULL) {
		memset(output_key, 0, key_byte_length);
		free(output_key);
	}
	if (master_secret != NULL) {
		memset(master_secret, 0, master_secret_len);
		free(master_secret);
	}
	return ret;
}
