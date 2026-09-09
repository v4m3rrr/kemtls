#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define TLS13_CIPHER_SUIT "TLS13-AES128-GCM-SHA256"
#define DOMAIN_NAME "example.com"

int main(int argc, char **argv)
{
	int ret;
	const char *ip_str;
	int port;
	int s_fd;
	struct sockaddr_in addr;

	WOLFSSL_CTX *ctx;
	WOLFSSL *ssl;
	int err;
	char error_buf[WOLFSSL_MAX_ERROR_SZ];

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
		return -1;
	}

	ip_str = argv[1];
	port = atoi(argv[2]);

	if (port == 0) {
		fprintf(stderr, "Incorrect port number\n");
		return -1;
	}

	ret = 0;

	if ((s_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Failed to create socket");
		ret = -1;
		return ret;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip_str, &addr.sin_addr) != 1) {
		fprintf(stderr, "Failed to convert address\n");
		ret = -1;
		goto error;
	}
	if (connect(s_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("Failed to connect");
		ret = -1;
		goto error;
	}

	printf("Connected to %s:%d\n", ip_str, port);

	if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
		fprintf(stderr, "failed to initialize wolfSSL library\n");
		goto error;
	}

#ifndef NDEBUG
	if (wolfSSL_Debugging_ON() != 0) {
		fprintf(stderr, "Logging is not enabled for this build");
		ret = -1;
		goto error_wolf;
	}
#endif
	if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL) {
		fprintf(stderr, "Failed to create wolfSSL context\n");
		ret = -1;
		goto error_wolf;
	}

	// TODO Change to SSL_VERIFY_PEER and load_verify_locations
	wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
	wolfSSL_CTX_set_session_cache_mode(ctx, WOLFSSL_SESS_CACHE_OFF);
	wolfSSL_CTX_set_cipher_list(ctx, TLS13_CIPHER_SUIT);
	wolfSSL_CTX_set_options(
		ctx, WOLFSSL_OP_NO_RENEGOTIATION |
			     WOLFSSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

	if ((ssl = wolfSSL_new(ctx)) == NULL) {
		fprintf(stderr, "Failed to create WOLFSSL object\n");
		ret = -1;
		goto error_wolf_ctx;
	}

	wolfSSL_set_fd(ssl, s_fd);

	// TODO provide correct domain name
	/*
	if ((ret = wolfSSL_check_domain_name(ssl, DOMAIN_NAME)) !=
	    WOLFSSL_SUCCESS) {
		err = wolfSSL_get_error(ssl, ret);
		fprintf(stderr,
			"Failed to enable check domain name."
			"error = %d, %s\n",
			err, wolfSSL_ERR_error_string(err, error_buf));
		ret = -1;
		goto error_wolf_obj;
	}
*/
	if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
		err = wolfSSL_get_error(ssl, ret);
		fprintf(stderr,
			"Failed to accept connection."
			"error = %d, %s\n",
			err, wolfSSL_ERR_error_string(err, error_buf));
		ret = -1;
		goto error_wolf_obj;
	}

	while ((ret = wolfSSL_shutdown(ssl)) != WOLFSSL_SUCCESS) {
		if (ret == WOLFSSL_FATAL_ERROR) {
			err = wolfSSL_get_error(ssl, ret);
			fprintf(stderr,
				"Failed to accept connection."
				"error = %d, %s\n",
				err, wolfSSL_ERR_error_string(err, error_buf));
			ret = -1;
			goto error_wolf_obj;
		} else if (ret == SSL_SHUTDOWN_NOT_DONE) {
			continue;
		} else {
			fprintf(stderr, "FATAL: impossible state reached\n");
			abort();
		}
	}

error_wolf_obj:
	wolfSSL_free(ssl);
error_wolf_ctx:
	wolfSSL_CTX_free(ctx);
error_wolf:
	wolfSSL_Cleanup();
error:
	close(s_fd);
	return ret;
}
