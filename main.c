
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
	size_t key_byte_length = 16;
	uint8_t* output_key = NULL;
	const char* output_key_filename = NULL;
	FILE* output_key_file = NULL;

	BEGIN_LONG_ARGUMENTS(ret)
	HANDLE_LONG_ARGUMENT("input")
	{
		master_secret_filename = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("output")
	{
		output_key_filename = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("key-identifier")
	{
		key_identifier = argv[++i];
	}
	HANDLE_LONG_ARGUMENT("key-length")
	{
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
		//print_arg_list_help(option_list,
		//	argv[0],"[args]");
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
		//print_arg_list_help(option_list,
		//	argv[0], "[args]");
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
			master_secret, MASTER_SECRET_BLOCK_SIZE,
			1, master_secret_file
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
	}

	if (output_key_file == NULL) {
		output_key = calloc(key_byte_length, 1);

		MSECRET_Extract(
			output_key, key_byte_length,
			key_identifier,
			master_secret, master_secret_len
		);

		hex_dump(stdout, output_key, key_byte_length, "");
		fprintf(stdout, "\n");
	} else {
		int written;
		written = MSECRET_ExtractToFILE(
			output_key_file, key_byte_length,
			key_identifier,
			master_secret, master_secret_len
		);
		if (written < 0) {
			fprintf(stderr, "Write failure: %d %s\n", errno, strerror(errno));
			ret = EXIT_FAILURE;
		} else {
			fprintf(stderr, "%d bytes written\n", written);
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
