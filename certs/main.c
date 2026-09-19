#include <stdio.h>

#include "codes.h"

#include "sig_algo.h"
#include "gen_key.h"

#define BUF_SZ 8192

int main(int argc, char **argv)
{
	int ret;
	unsigned char buf[BUF_SZ];
	int buf_sz;
	FILE *fd;
	int key_type;
	const char *filename;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <KEY_TYPE> <FILE>\n", argv[0]);
		return CODE_ERROR;
	}

	if ((key_type = get_key_type_from_str(argv[1])) == CODE_ERROR) {
		fprintf(stderr, "Unknown key type. Provided: %s\n", argv[1]);
		return CODE_ERROR;
	}

	filename = argv[2];

	ret = CODE_OK;

	if ((ret = sig_algo_init()) != CODE_OK) {
		fprintf(stderr, "failed to initialise gen_key\n");
		return CODE_ERROR;
	}
	struct KeyUni key = gen_key_create(key_type);
	if (key.key == NULL) {
		fprintf(stderr, "failed to allocate memory for key\n");
		return CODE_ERROR;
	}

	if ((ret = gen_key(key)) != CODE_OK) {
		fprintf(stderr, "failed to initialise gen_key\n");
		return CODE_ERROR;
	}

	buf_sz = BUF_SZ;
	if ((ret = key_to_der(key, buf, &buf_sz)) != CODE_OK) {
		fprintf(stderr, "failed to generate key\n");
		ret = CODE_ERROR;
		goto error;
	}

	fd = fopen(filename, "w");
	if (fd == NULL) {
		perror("failed to open a file");
		ret = CODE_ERROR;
		goto error;
	}
	if (fwrite(buf, sizeof(*buf), buf_sz, fd) != buf_sz) {
		if (ferror(fd) != 0) {
			perror("failed to write to a file");
			ret = CODE_ERROR;
			goto err_file_close;
		}
	}

	ret = CODE_OK;
err_file_close:
	if (fclose(fd)) {
		perror("failed to close a file");
		ret = CODE_ERROR;
	}
error:
	if (sig_algo_cleanup() != CODE_OK) {
		fprintf(stderr, "failed to cleanup gen_key\n");
		ret = CODE_ERROR;
	}
	return ret;
}
