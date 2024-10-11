#ifndef SSL_H
#define SSL_H

#include <openssl/ssl.h>

void setup_ssl_bio(int fd);
int setup_ssl_accept(SSL *ssl, int fd);
int setup_ssl_connect(SSL *ssl, int fd, char *host, int port);
int setup_ssl_context(SSL_CTX *ctx, char *server_private_key,
                      char *server_certificate);
int ssl_check_error(SSL *ssl, int ret);
int read_ssl(SSL *ssl, char *buf, int buf_size);
int write_ssl(SSL *ssl, char *buf);

#endif