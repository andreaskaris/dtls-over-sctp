#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ssl.h"

/*
 * struct connection_info is passed as an argument to pthread_create for
 * serve_connection. It allows us to pass multiple arguments to our thread.
 */
struct connection_info {
  int fd;
  SSL_CTX *ctx;
};

/*
 * listen_on_sctp_socket is used by the server to listen on an SCTP socket.
 * This function is generic and can be used for both SCTP with and without DTLS
 * on top of it.
 */
int listen_on_sctp_socket(char *host, int port) {
  int fd;
  struct sockaddr_in server_addr;

  // Create SCTP socket:
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  if (fd < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  printf("Socket created successfully\n");

  // Set port and IP:
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(host);

  // Bind to the set port and IP:
  if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    printf("Couldn't bind to the port\n");
    return -1;
  }
  printf("Done with binding\n");

  /* Specify that a maximum of 10 streams will be available per socket */
  struct sctp_initmsg initmsg;
  memset(&initmsg, 0, sizeof(initmsg));
  initmsg.sinit_num_ostreams = 10;
  initmsg.sinit_max_instreams = 10;
  initmsg.sinit_max_attempts = 4;
  if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) <
      0) {
    printf("setsockopt() failed \n");
    perror("setsockopt()");
    close(fd);
    return 1;
  }

  printf("Listening for incoming messages...\n\n");
  if (listen(fd, 10) < 0) {
    printf("Couldn't listen on port\n");
    return -1;
  }
  return fd;
}

/*
 * serve_connection runs in a pthread for each accepted connection. It is
 * responsible for receiving messages from the clients and answering to them.
 */
void *serve_connection(void *arg) {
  pthread_detach(pthread_self());

  // Create buffers for server messages.
  char server_message[2000], client_message[2000];
  memset(server_message, '\0', sizeof(server_message));
  memset(client_message, '\0', sizeof(client_message));

  // Read args.
  struct connection_info *cinfo = (struct connection_info *)arg;
  int afd = cinfo->fd;
  SSL_CTX *ctx = cinfo->ctx;

  // Create new SSL structure.
  SSL *ssl = SSL_new(ctx);

  if (setup_ssl_accept(ssl, afd) == 0) {
    while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
      if (read_ssl(ssl, client_message, sizeof(client_message)) < 0) {
        goto cleanup_connection;
      }
      printf("Msg from client: '%s'\n", client_message);

      // Respond to client:
      strcpy(server_message, client_message);
      printf("Answer to client: '%s'\n", server_message);
      if (write_ssl(ssl, server_message) != 0) {
        goto cleanup_connection;
      }
    }
  }

cleanup_connection:
  printf("Cleaning up serve_connection\n");
  // SSL_shutdown is non-blocking and will return 0 to indicate that the
  // shutdown has not yet finished.
  // Check:
  // https://docs.openssl.org/master/man7/ossl-guide-quic-client-non-block/#shutting-down-the-connection
  int ret;
  while ((ret = SSL_shutdown(ssl)) != 1) {
    if (ret < 0 && ssl_check_error(ssl, ret) == 1) {
      continue; /* Retry */
    }
    break;
  }
  close(afd);
  SSL_free(ssl);
}

/*
 * server runs the DTLS over SCTP server. It takes a listen address, listen port
 * and server private key and certificate. It then setups up an SSL context and
 * starts listening on SCTP:host:port. Next, it instructs the underlying socket
 * to use SCTP-AUTH which is a prerequisite for DTLS over SCTP. Note that
 * `net.sctp.auth_enable = 1` must be set to instruct the kernel to handle SCTP
 * auth chunks. Then, the server will go into a loop and listen for new SCTP
 * connections. Whenever a connection is accepted, the server will create a new
 * pthread which runs server_connection with the accepted file descriptor as
 * well as the SSL context.
 */
int server(char *host, int port, char *server_private_key,
           char *server_certificate) {
  pthread_t tid;
  struct sockaddr_in client_addr;
  socklen_t client_struct_length = sizeof(client_addr);
  struct connection_info *cinfo;

  SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
  if (setup_ssl_context(ctx, server_private_key, server_certificate) != 0) {
    return -1;
  }

  // Set up the listen socket first.
  int fd = listen_on_sctp_socket(host, port);
  if (fd < 0) {
    return -1;
  }

  /* Create BIO to set all necessary parameters for
   * following connections, e.g. SCTP-AUTH.
   * Otherwise, we'll get:
   * "Ensure SCTP AUTH chunks are enabled on the underlying socket"
   * This BIO will not be used other than for error verification
   */
  setup_ssl_bio(fd);

  while (true) {
    // Reset client_addr to 0.
    memset(&client_addr, 0, sizeof(client_addr));
    // Block until a new connecton is made from the client and accept it.
    int afd =
        accept(fd, (struct sockaddr *)&client_addr, &client_struct_length);
    if (afd < 0) {
      printf("Couldn't accept\n");
      close(fd);
      return -1;
    }

    cinfo = (struct connection_info *)malloc(sizeof(struct connection_info));
    memset(cinfo, 0, sizeof(struct connection_info));
    cinfo->fd = afd;
    cinfo->ctx = ctx;
    // Serve the connection.
    if (pthread_create(&tid, NULL, serve_connection, cinfo) != 0) {
      printf("Couldn't serve connection");
      close(fd);
      return -1;
    }
  }
  close(fd);
  return 0;
}
