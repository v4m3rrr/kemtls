#include <stdio.h>

#include "sig_algo.h"
#include "gen_key.h"
#include "cert_gen.h"
#include "codes.h"

int main()
{
	int ret;
	unsigned char der[10000];
	int der_sz = 10000;
	unsigned char der_root[10000];
	int der_root_sz = 10000;
	unsigned char der_key[10000];
	int der_key_sz = 10000;

	const char *dns_entries[] = { "raspberrypi.local" };
	const unsigned char ip_entries[][4] = { { 192, 168, 1, 100 },
						{ 127, 0, 0, 1 } };
	if ((ret = sig_algo_init()) != CODE_OK) {
		fprintf(stderr, "failed to init sig algo\n");
		ret = CODE_ERROR;
		return ret;
	}

	int algo = SIG_ALGO_MLKEM_512;
	int root_algo = SIG_ALGO_ED25519;

	struct KeyUni key_root = gen_key_create(root_algo);
	if ((ret = gen_key(key_root)) != CODE_OK) {
		fprintf(stderr, "failed to generate root key\n");
		ret = CODE_ERROR;
		goto err;
	}

	Cert *cert;
	if ((cert = cert_create(root_algo, NULL, 0, NULL, 0, "Cert generator",
				"Root CA", 1, 1)) == NULL) {
		fprintf(stderr, "failed to create root certificate\n");
		ret = CODE_ERROR;
		goto err2;
	}

	if ((ret = cert_gen(cert, der_root, &der_root_sz, NULL, 0, key_root,
			    key_root)) != CODE_OK) {
		fprintf(stderr, "failed to generate root certificate\n");
		ret = CODE_ERROR;
		goto err3;
	}

	Cert *serv_cert;
	if ((serv_cert = cert_create(root_algo, NULL, 0, NULL, 0, "MA thesis",
				     "Server", 0, -1)) == NULL) {
		fprintf(stderr, "failed to create serv certificate\n");
		ret = CODE_ERROR;
		goto err3;
	}

	struct KeyUni key_sub = gen_key_create(algo);
	if ((ret = gen_key(key_sub)) != CODE_OK) {
		fprintf(stderr, "failed to generate sub key\n");
		ret = CODE_ERROR;
		goto err4;
	}

	if ((ret = key_to_der(key_sub, der_key, &der_key_sz)) != CODE_OK) {
		fprintf(stderr, "failed to convert sub key to der\n");
		goto err5;
	}

	if ((ret = cert_gen(serv_cert, der, &der_sz, der_root, der_root_sz,
			    key_sub, key_root)) != CODE_OK) {
		fprintf(stderr, "failed to generate serv certificate\n");
		ret = CODE_ERROR;
		goto err5;
	}

	FILE *fd;
	fd = fopen("cert.der", "w");

	fwrite(der, sizeof(*der), der_sz, fd);
	fclose(fd);

	fd = fopen("cert_root.der", "w");

	fwrite(der_root, sizeof(*der_root), der_root_sz, fd);
	fclose(fd);

	fd = fopen("server.der", "w");

	fwrite(der_key, sizeof(*der_key), der_key_sz, fd);
	fclose(fd);
err5:
	gen_key_free(key_sub);
err4:
	cert_free(serv_cert);
err3:
	cert_free(cert);
err2:
	gen_key_free(key_root);
err:
	sig_algo_cleanup();
	return 0;
}
