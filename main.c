
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "msecret.h"
#include "lkdf.h"
#include "help.h"
#include <sys/errno.h>
#include <inttypes.h>
#include "hmac_sha/sha2.h"
#define HEADER_SHA_H 1
#define SHA_DIGEST_LENGTH (160/8)
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include "base58.h"
#include "base32.h"


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
	{ 0, "key-max",	"n", "Maximum numerical value for key"				},
	{ 'l', "key-length",	"bytes", "key length, in bytes"				},
	{   0, "format-bin",	NULL, "Output raw binary key"				},
	{   0, "format-hex",	NULL, "Output hexidecimal key"				},
	{   0, "format-dec",	NULL, "Output decimal key"				},
	{   0, "format-b58",	NULL, "Output Base58 key"				},
	{ 0, "dec-zero-fill", "X", "Zero fill key to X places"},
	{ 0, "integer",	NULL, "Derive a large integer (default)"				},
	{ 0, "prime",	NULL, "Derive a large prime"				},
	{ 0, "rsa",	NULL, "Derive a RSA private key"				},
	{ 0, "rsa-public",	NULL, "Derive an RSA public key"				},
	{ 0, "bitcoin-priv",	NULL, "Derive a bitcoin private key"				},
	{ 0, "bitcoin-addr",	NULL, "Derive the associated bitcoin address"				},
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
		TYPE_RSA_PUBLIC,
		TYPE_EC,
		TYPE_EC_PUBLIC,
		TYPE_DSA_PARAM,
		TYPE_BITCOIN_PRIV,
		TYPE_BITCOIN_ADDR,
	} secret_type;
	bool gen_prime=false;

	enum {
		OUTPUT_UNSPECIFIED,
		OUTPUT_RAW,
		OUTPUT_HEX,
		OUTPUT_DEC,
		OUTPUT_B64,
		OUTPUT_B32,
		OUTPUT_B58,
	} output_format = OUTPUT_UNSPECIFIED;
	RSA *rsa = NULL;

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
	HANDLE_LONG_ARGUMENT("format-raw")
	{
		output_format = OUTPUT_RAW;
	}
	HANDLE_LONG_ARGUMENT("format-bin")
	{
		output_format = OUTPUT_RAW;
	}
	HANDLE_LONG_ARGUMENT("integer")
	{
		secret_type = TYPE_INTEGER;
	}
	HANDLE_LONG_ARGUMENT("prime")
	{
		secret_type = TYPE_PRIME;
	}
	HANDLE_LONG_ARGUMENT("bitcoin-priv")
	{
		secret_type = TYPE_BITCOIN_PRIV;
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
	}
	HANDLE_LONG_ARGUMENT("bitcoin-addr")
	{
		secret_type = TYPE_BITCOIN_ADDR;
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
	}
	HANDLE_LONG_ARGUMENT("rsa")
	{
		secret_type = TYPE_RSA;
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_RAW;
			output_format = OUTPUT_B64;
		}
	}
	HANDLE_LONG_ARGUMENT("rsa-public")
	{
		secret_type = TYPE_RSA_PUBLIC;
		if (output_format == OUTPUT_UNSPECIFIED) {
			output_format = OUTPUT_RAW;
			output_format = OUTPUT_B64;
		}
	}
	HANDLE_LONG_ARGUMENT("key-identifier")
	{
		key_identifier = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("dec-zero-fill")
	{
		zero_fill_digits = (unsigned int)strtol(argv[++i], NULL, 0);
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


	if (secret_type == TYPE_BITCOIN_PRIV
		|| secret_type == TYPE_BITCOIN_ADDR
	) {
		static const uint8_t bitcoin_mod[] = {
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFE,
			0xBA, 0xAE, 0xDC, 0xE6,
			0xAF, 0x48, 0xA0, 0x3B,
			0xBF, 0xD2, 0x5E, 0x8C,
			0xD0, 0x36, 0x41, 0x41,
		};

		key_byte_length = sizeof(bitcoin_mod);

		key_max = calloc(sizeof(bitcoin_mod), 1);
		if (key_max == NULL) {
			fprintf(stderr, "Malloc failure\n");
			ret = EXIT_FAILURE;
			goto bail;
		}

		memcpy(key_max, bitcoin_mod, sizeof(bitcoin_mod));
	}


	if (key_byte_length == -1) {
		// Default key length is 128 bit (16 bytes).
		key_byte_length = 16;
	}

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

#define MASTER_SECRET_BLOCK_SIZE (1024*4)
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
		} else if ((secret_type == TYPE_RSA) || (secret_type == TYPE_RSA_PUBLIC)) {
			rsa = RSA_new();
			MSECRET_Extract_RSA(
				rsa,
			    key_byte_length*8,
				0,
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

	if (secret_type == TYPE_RSA) {
		if(debug_mode)RSA_print_fp(stderr, rsa, 0);
		switch (output_format) {
		case OUTPUT_UNSPECIFIED:
		case OUTPUT_RAW:
			i2d_RSAPrivateKey_fp(stdout,rsa);
			break;
		case OUTPUT_B64:
			{
				EVP_PKEY* private_key = EVP_PKEY_new();
				EVP_PKEY_set1_RSA(private_key, rsa);
				PEM_write_PrivateKey(
					stdout,
					private_key,
					NULL,
					NULL, 0, NULL, NULL
				);
				EVP_PKEY_free(private_key);
			}
			break;
		default:
			fprintf(stderr, "Invalid output format\n");
			ret = EXIT_FAILURE;
			goto bail;
			break;
		}
	} else if (secret_type == TYPE_RSA_PUBLIC) {
		if(debug_mode)RSA_print_fp(stderr, rsa, 0);
		switch (output_format) {
		case OUTPUT_UNSPECIFIED:
		case OUTPUT_RAW:
			i2d_RSAPublicKey_fp(stdout,rsa);
			break;
		case OUTPUT_B64:
			{
				EVP_PKEY* private_key = EVP_PKEY_new();
				EVP_PKEY_set1_RSA(private_key, rsa);
				PEM_write_RSAPublicKey(
					stdout,
					rsa
				);
				EVP_PKEY_free(private_key);
			}
			break;
		default:
			fprintf(stderr, "Invalid output format\n");
			ret = EXIT_FAILURE;
			goto bail;
			break;
		}
	} else {
		if (secret_type == TYPE_BITCOIN_PRIV) {
			uint8_t tmp[SHA256_DIGEST_LENGTH];
			EVP_MD_CTX md_ctx;

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
		} else if (secret_type == TYPE_BITCOIN_ADDR) {
			EC_KEY *ec_key;
			EC_POINT *ec_pub_key;
			BIGNUM bn_key;
			BIGNUM bn_x, bn_y;
			uint8_t byte_x[32], byte_y[32];
			const EC_GROUP *group = NULL;
			EVP_MD_CTX md_ctx;
			char hdr = 0x04;
			//unsigned int dgstlen = 32;
			uint8_t tmp[SHA256_DIGEST_LENGTH];

			BN_init(&bn_key);
			BN_init(&bn_x);
			BN_init(&bn_y);
			ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
			group = EC_KEY_get0_group(ec_key);
			ec_pub_key = EC_POINT_new(group);

			BN_bin2bn(output_key, key_byte_length, &bn_key);
			EC_KEY_set_private_key(ec_key, &bn_key);

			if (!EC_POINT_mul(group, ec_pub_key, &bn_key, NULL, NULL, NULL)) {
				fprintf(stderr,"Error at EC_POINT_mul.\n");
				ret = EXIT_FAILURE;
				goto bail;
			}

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
					fprintf(stdout, format_string, v);
					free(format_string);

	/*
				} else if (key_byte_length <= 8) {
					uint64_t v = 0;
					memcpy(((uint8_t*)&v)+8-key_byte_length, output_key, key_byte_length);
					v = htonll(v);
					fprintf(stdout, "%llu\n", v);
	*/
				} else {
					fprintf(stderr, "Key size too large for decimal mode\n");
					ret = EXIT_FAILURE;
				}
			}
			break;
		case OUTPUT_HEX:
			hex_dump(stdout, output_key, key_byte_length, "");
			fprintf(stdout, "\n");
			break;
		case OUTPUT_B58:
			{
				char output_string[key_byte_length*4];
				output_string[0] = 0;

				fprintf(stdout, "%s\n", encode_base58(output_string, sizeof(output_string), output_key, key_byte_length));
			}
			break;
		case OUTPUT_B32:
			{
				char output_string[key_byte_length*4];
				output_string[0] = 0;

				base32_encode(output_key, key_byte_length, (unsigned char*)output_string);
				fprintf(stdout, "%s\n", output_string);
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
				written = fwrite(output_key,key_byte_length,1,output_key_file);
				if (written < 0) {
					fprintf(stderr, "Write failure: %d %s\n", errno, strerror(errno));
					ret = EXIT_FAILURE;
				} else {
					fprintf(stderr, "%d bytes written\n", written);
				}
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
