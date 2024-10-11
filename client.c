#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <openssl/cryptoerr_legacy.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>

#include "ssl.h"

/*
 * client implements the client. It takes a destination host and port number as
 * well as the client private key and certificate. It then establishes a
 * connection to the server, negotiates DTLS and sends a message num_messages
 * times.
 */
int client(char *host, int port, char *client_private_key,
           char *client_certificate, char *client_message, int num_messages) {
  int fd;
  char client_message_with_index[2000]; /* Not safe as longer than client */
                                        /* message but good enough here. */
  char server_message[2000];
  struct sctp_sndrcvinfo sndrcvinfo;
  int flags = 0;

  // Clean buffers:
  memset(server_message, '\0', sizeof(server_message));
  // memset(client_message, '\0', sizeof(client_message));

  // Create socket:
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  if (fd < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  printf("Socket created successfully\n");

  // Setup SSL context and connect call.
  SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
  if (setup_ssl_context(ctx, client_private_key, client_certificate) != 0) {
    return -1;
  }
  SSL *ssl = SSL_new(ctx);
  if (setup_ssl_connect(ssl, fd, host, port) < 0) {
    return -1;
  }

  // Main logic. Write message num_messages times and print the answer.
  int i = 0;
  while (i < num_messages && !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
    sprintf(client_message_with_index, "%s (%d)", client_message, i);
    printf("Sending message: '%s'\n", client_message_with_index);
    if (write_ssl(ssl, client_message_with_index) == 0) {
      if (read_ssl(ssl, server_message, sizeof(server_message)) == 0) {
        printf("Server's response: '%s'\n", server_message);
      }
    }
    i++;
  }

  // Close the SSL connection and the socket.
  printf("Cleaning up client connection\n");
  // SSL_shutdown is non-blocking and will return 0 to indicate that the
  // shutdown has not yet finished. Check:
  // https://docs.openssl.org/master/man7/ossl-guide-quic-client-non-block/#shutting-down-the-connection
  int ret;
  while ((ret = SSL_shutdown(ssl)) != 1) {
    if (ret < 0 && ssl_check_error(ssl, ret) == 1) {
      continue; /* Retry */
    }
    break;
  }
  close(fd);

  return 0;
}