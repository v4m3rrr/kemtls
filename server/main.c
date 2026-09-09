#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/logging.h>

#define TLS13_CIPHER_SUIT "TLS13-AES128-GCM-SHA256"

int main(int argc, char **argv)
{
	int ret;
	int port;
	const char *l_addr_str;
	int l_fd;
	struct sockaddr_in l_addr;
	int enable;

	WOLFSSL_CTX *ctx;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
		return -1;
	}

	l_addr_str = argv[1];
	port = atoi(argv[2]);

	if (port == 0) {
		fprintf(stderr, "Incorrect port number\n");
		return -1;
	}

	if ((l_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Creation of listenning socket failed");
		return -1;
	}

	enable = 1;
	setsockopt(l_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

	enable = 1;
	setsockopt(l_fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));

	l_addr.sin_family = AF_INET;
	l_addr.sin_port = htons(port);
	if (inet_pton(AF_INET, l_addr_str, &l_addr.sin_addr) <= 0) {
		fprintf(stderr, "Failed to convert IPv4 address\n");
		ret = -1;
		goto error;
	}

	if (bind(l_fd, (struct sockaddr *)&l_addr, sizeof(l_addr)) == -1) {
		perror("Failed to bind socket to address");
		ret = -1;
		goto error;
	}

	if (listen(l_fd, 1) == -1) {
		perror("Failed to listen on socket");
		ret = -1;
		goto error;
	}

	printf("Listening on %s:%d\n", l_addr_str, port);

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
	if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method())) == NULL) {
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

	if (wolfSSL_CTX_use_certificate_file(ctx, "./server.pem",
					     WOLFSSL_FILETYPE_PEM) !=
	    WOLFSSL_SUCCESS) {
		fprintf(stderr, "Failed to load certificate file\n");
		ret = -1;
		goto error_wolf_ctx;
	}

	if (wolfSSL_CTX_use_PrivateKey_file(ctx, "./server.key",
					    WOLFSSL_FILETYPE_PEM) !=
	    WOLFSSL_SUCCESS) {
		fprintf(stderr, "Failed to load private key file\n");
		ret = -1;
		goto error_wolf_ctx;
	}

	for (;;) {
		socklen_t c_addr_len;
		int c_fd;
		struct sockaddr_in c_addr;
		char c_addr_str[INET_ADDRSTRLEN];
		int c_port;
		WOLFSSL *ssl;
		int err;
		char error_buf[WOLFSSL_MAX_ERROR_SZ];

		c_addr_len = sizeof(c_addr);
		if ((c_fd = accept(l_fd, (struct sockaddr *)&c_addr,
				   &c_addr_len)) == -1) {
			perror("Failed to accept connection");
			ret = -1;
			goto error_wolf_ctx;
		}
		if (inet_ntop(AF_INET, &c_addr.sin_addr, c_addr_str,
			      INET_ADDRSTRLEN) == NULL) {
			perror("Failed to convert IPv4 address");
			close(c_fd);
			ret = -1;
			goto error_wolf_ctx;
		}

		c_port = ntohs(c_addr.sin_port);
		printf("Established connection with %s on port %d\n",
		       c_addr_str, c_port);

		if ((ssl = wolfSSL_new(ctx)) == NULL) {
			fprintf(stderr, "Failed to create WOLFSSL object\n");
			ret = -1;
			close(c_fd);
			goto error_wolf_ctx;
		}

		wolfSSL_set_fd(ssl, c_fd);

		if ((ret = wolfSSL_accept(ssl)) != WOLFSSL_SUCCESS) {
			err = wolfSSL_get_error(ssl, ret);
			fprintf(stderr,
				"Failed to accept connection."
				"error = %d, %s\n",
				err, wolfSSL_ERR_error_string(err, error_buf));
			ret = -1;
			wolfSSL_free(ssl);
			close(c_fd);
			goto error_wolf_ctx;
		}

		while ((ret = wolfSSL_shutdown(ssl)) != WOLFSSL_SUCCESS) {
			if (ret == WOLFSSL_FATAL_ERROR) {
				err = wolfSSL_get_error(ssl, ret);
				fprintf(stderr,
					"Failed to accept connection."
					"error = %d, %s\n",
					err,
					wolfSSL_ERR_error_string(err,
								 error_buf));
				ret = -1;
				wolfSSL_free(ssl);
				close(c_fd);
				goto error_wolf_ctx;
			} else if (ret == SSL_SHUTDOWN_NOT_DONE) {
				continue;
			} else {
				fprintf(stderr,
					"FATAL: impossible state reached\n");
				abort();
			}
		}

		wolfSSL_free(ssl);
		close(c_fd);
	}

	ret = 0;
error_wolf_ctx:
	wolfSSL_CTX_free(ctx);
error_wolf:
	wolfSSL_Cleanup();
error:
	close(l_fd);
	return ret;
}
