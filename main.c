
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "msecret.h"
#include "lkdf.h"
#include "help.h"
#include <sys/errno.h>
#include <inttypes.h>

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
	{ 0, "dec-zero-fill", "X", "Zero fill key to X places"},
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
		OUTPUT_UNSPECIFIED,
		OUTPUT_RAW,
		OUTPUT_HEX,
		OUTPUT_DEC,
		OUTPUT_B64,
		OUTPUT_B32,
	} output_format = OUTPUT_UNSPECIFIED;

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

	output_key = calloc(key_byte_length, 1);

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
		// Extracts a random key with a length of
		// key_byte_length.
		MSECRET_Extract_Bytes(
			output_key, key_byte_length,
			key_selector,
			master_secret, master_secret_len
		);
	} else {
		// Extracts a key that is less than or
		// equal to the specific value of key_max.
		MSECRET_Extract_Integer(
			output_key, key_max, key_byte_length,
			key_selector,
			master_secret, master_secret_len
		);
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
	default:
		fprintf(stderr, "Unknown output format\n");
		ret = EXIT_FAILURE;
		goto bail;
		break;
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
