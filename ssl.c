#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <stdbool.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/* handle_notification is copied verbatim from
 * https://github.com/nplab/DTLS-Examples/blob/master/src/dtls_sctp_echo.c
 * It is used in both setup_ssl_accept and setup_ssl_connect (so for client and
server) with:
 * "BIO_dgram_sctp_notification_cb(bio, &handle_notifications, (void *)ssl);"
 */
void handle_notifications(BIO *bio, void *context, void *buf) {
  struct sctp_assoc_change *sac;
  struct sctp_send_failed *ssf;
  struct sctp_paddr_change *spc;
  struct sctp_remote_error *sre;
  union sctp_notification *snp = buf;
  char addrbuf[INET6_ADDRSTRLEN];
  const char *ap;
  union {
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    struct sockaddr_storage ss;
  } addr;

  switch (snp->sn_header.sn_type) {
  case SCTP_ASSOC_CHANGE:
    sac = &snp->sn_assoc_change;
    printf("NOTIFICATION: assoc_change: state=%hu, error=%hu, instr=%hu "
           "outstr=%hu\n",
           sac->sac_state, sac->sac_error, sac->sac_inbound_streams,
           sac->sac_outbound_streams);
    break;

  case SCTP_PEER_ADDR_CHANGE:
    spc = &snp->sn_paddr_change;
    addr.ss = spc->spc_aaddr;
    if (addr.ss.ss_family == AF_INET) {
      ap = inet_ntop(AF_INET, &addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN);
    } else {
      ap = inet_ntop(AF_INET6, &addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN);
    }
    printf("NOTIFICATION: intf_change: %s state=%d, error=%d\n", ap,
           spc->spc_state, spc->spc_error);
    break;

  case SCTP_REMOTE_ERROR:
    sre = &snp->sn_remote_error;
    printf("NOTIFICATION: remote_error: err=%hu len=%hu\n",
           ntohs(sre->sre_error), ntohs(sre->sre_length));
    break;

  case SCTP_SEND_FAILED:
    ssf = &snp->sn_send_failed;
    printf("NOTIFICATION: sendfailed: len=%u err=%d\n", ssf->ssf_length,
           ssf->ssf_error);
    break;

  case SCTP_SHUTDOWN_EVENT:
    printf("NOTIFICATION: shutdown event\n");
    break;

  case SCTP_ADAPTATION_INDICATION:
    printf("NOTIFICATION: adaptation event\n");
    break;

  case SCTP_PARTIAL_DELIVERY_EVENT:
    printf("NOTIFICATION: partial delivery\n");
    break;

#ifdef SCTP_AUTHENTICATION_EVENT
  case SCTP_AUTHENTICATION_EVENT:
    printf("NOTIFICATION: authentication event\n");
    break;
#endif

#ifdef SCTP_SENDER_DRY_EVENT
  case SCTP_SENDER_DRY_EVENT:
    printf("NOTIFICATION: sender dry event\n");
    break;
#endif

  default:
    printf("NOTIFICATION: unknown type: %hu\n", snp->sn_header.sn_type);
    break;
  }
}

/*
 * setup_ssl_bio is a wrapper around BIO_new_dgram_sctp(fd, BIO_NOCLOSE).
 */
BIO *setup_ssl_bio(int fd) {
  BIO *bio = BIO_new_dgram_sctp(fd, BIO_NOCLOSE);
  if (!bio) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  return bio;
}

/*
 * print_connect_accept_failure is a helper function that's used to reduce code
 * duplication. When SSL_connect (client) or SSL_accept (server) fail, the error
 * handling is the same. Avoid code duplication by moving here.
 */
int print_connect_accept_failure(SSL *ssl, int ret) {
  switch (SSL_get_error(ssl, ret)) {
  case SSL_ERROR_ZERO_RETURN:
    fprintf(stderr, "with SSL_ERROR_ZERO_RETURN\n");
    return -1;
  case SSL_ERROR_WANT_READ:
    fprintf(stderr, "with SSL_ERROR_WANT_READ\n");
    return -1;
  case SSL_ERROR_WANT_WRITE:
    fprintf(stderr, "with SSL_ERROR_WANT_WRITE\n");
    return -1;
  case SSL_ERROR_WANT_CONNECT:
    fprintf(stderr, "with SSL_ERROR_WANT_CONNECT\n");
    return -1;
  case SSL_ERROR_WANT_ACCEPT:
    fprintf(stderr, "with SSL_ERROR_WANT_ACCEPT\n");
    return -1;
  case SSL_ERROR_WANT_X509_LOOKUP:
    fprintf(stderr, "with SSL_ERROR_WANT_X509_LOOKUP\n");
    return -1;
  case SSL_ERROR_SYSCALL:
    fprintf(stderr, "with SSL_ERROR_SYSCALL\n");
    return -1;
  case SSL_ERROR_SSL:
    fprintf(stderr, "with SSL_ERROR_SSL\n");
    return -1;
  default:
    fprintf(stderr, "with unknown error\n");
    return -1;
  }
}

/*
 * setup_ssl_accept takes an SSL struct and a file descriptor of an already
 * accepted SCTP connection. It will set up an SSL Basic Input Output (BIO) with
 * the file descriptor and it will then connect the SSL object with the BIO.
 * It then uses SSL_accept to wait for the TLS client to initiate the TLS
 * handshake.
 */
int setup_ssl_accept(SSL *ssl, int fd) {
  /* Create DTLS/SCTP BIO */
  BIO *bio = setup_ssl_bio(fd);

  SSL_set_bio(ssl, bio, bio);
  BIO_dgram_sctp_notification_cb(bio, &handle_notifications, (void *)ssl);

  int ret = SSL_accept(ssl);
  if (ret <= 0) {
    printf("SSL_accept failed with ");
    return print_connect_accept_failure(ssl, ret);
  }

  if (SSL_get_peer_certificate(ssl)) {
    printf("------------------------------------------------------------\n");
    X509_NAME_print_ex_fp(stdout,
                          X509_get_subject_name(SSL_get_peer_certificate(ssl)),
                          1, XN_FLAG_MULTILINE);
    printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
    printf(
        "\n------------------------------------------------------------\n\n");
  }

  return 0;
}

/*
 * setup_ssl_connect is used by the client to connect to a server's socket. It
 * takes an SSL struct which was created with "SSL_CTX *ctx =
 * SSL_CTX_new(DTLS_client_method());" -> "SSL *ssl = SSL_new(ctx);" and a file
 * descriptor to a new SCTP socket.
 * It then sets up an SSL Basic Input/Output (BIO) with the file descriptor. The
 * file descriptor is then used to connect to the server. Thereafter,
 * the SSL struct is set to use the BIO (which in turn uses the connected file
 * descriptor).
 * Last but not least, SSL_connect is used to initiae the TLS handshake with the
 * TLS server.
 * If possible, the function will also print the peer certificate.
 */
int setup_ssl_connect(SSL *ssl, int fd, char *host, int port) {
  int ret;
  struct sockaddr_in server_addr;
  int server_struct_length = sizeof(server_addr);

  /* Create DTLS/SCTP BIO */
  BIO *bio = setup_ssl_bio(fd);

  // Set port and IP:
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(host);
  // Send connection request to server:
  if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    printf("Unable to connect\n");
    return -1;
  }
  printf("Connected with server successfully\n");

  SSL_set_bio(ssl, bio, bio);
  BIO_dgram_sctp_notification_cb(bio, &handle_notifications, (void *)ssl);

  ret = SSL_connect(ssl);
  if (ret <= 0) {
    printf("SSL_connect failed with ");
    return print_connect_accept_failure(ssl, ret);
  }

  if (SSL_get_peer_certificate(ssl)) {
    printf("------------------------------------------------------------\n");
    X509_NAME_print_ex_fp(stdout,
                          X509_get_subject_name(SSL_get_peer_certificate(ssl)),
                          1, XN_FLAG_MULTILINE);
    printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
    printf(
        "\n------------------------------------------------------------\n\n");
  }

  return 0;
}

/*
 * setup_ssl_context can be used by both the client and the server to set up the
 * SSL context. Among other things, it sets up the certificate and private
 * private key. It also disables the verification of certificates for simplicity
 * reasons. In order to enable verification, see `man SSL_CTX_set_verify` and/or
 * https://github.com/nplab/DTLS-Examples/blob/master/src/dtls_sctp_echo.c#L213.
 */
int setup_ssl_context(SSL_CTX *ctx, char *private_key, char *pem_certificate) {
  // SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
  int pid = getpid();
  if (!SSL_CTX_set_session_id_context(ctx, (void *)&pid, sizeof pid))
    perror("SSL_CTX_set_session_id_context");

  printf("key: %s\n", private_key);
  printf("cert: %s\n", pem_certificate);

  if (!SSL_CTX_use_certificate_file(ctx, pem_certificate, SSL_FILETYPE_PEM))
    printf("\nERROR: no certificate found!");

  if (!SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM))
    printf("\nERROR: no private key found!");

  if (!SSL_CTX_check_private_key(ctx))
    printf("\nERROR: invalid private key!");

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  SSL_CTX_set_read_ahead(ctx, 1);

  return 0;
}

/* ssl_check_error takes an SSL struct and a return code. It extracts  the SSL
 * ERROR A positive return value signals SSL_ERROR_WANT_WRITE or
 * SSL_ERROR_WANT_READ. This means that the operation in question should be
 * tried again. 0 means success, and a negative return code indicates that issue
 * occurred. In such a case, ssl_check_error will also print an informative
 * message about the issue type.
 */
int ssl_check_error(SSL *ssl, int ret) {
  // https://docs.openssl.org/master/man3/SSL_get_error/#return-values
  switch (SSL_get_error(ssl, ret)) {
  case SSL_ERROR_NONE:
    // The TLS/SSL I/O operation completed. This result code is returned if
    // and only if ret > 0.
    return 0;
  case SSL_ERROR_WANT_WRITE:
    // The operation did not complete and can be retried later.
    // Note: No action taken in this example.
    printf("SSL_ERROR_WANT_WRITE\n");
    return 1;
  case SSL_ERROR_WANT_READ:
    // The operation did not complete and can be retried later.
    // Breaking here without returning -> read again
    printf("SSL_ERROR_WANT_READ\n");
    return 1;
  case SSL_ERROR_ZERO_RETURN:
    // The TLS/SSL peer has closed the connection for writing by sending the
    // close_notify alert. No more data can be read.
    return -1;
  case SSL_ERROR_SYSCALL:
    // Legacy, not used after OpenSSL v3.0.
    perror("Socket error");
    return -1;
  case SSL_ERROR_SSL:
    // A non-recoverable, fatal error in the SSL library occurred, usually a
    // protocol error.
    /*
     * Some stream fatal error occurred. This could be because of a
     * stream reset - or some failure occurred on the underlying
     * connection.
     */
    switch (SSL_get_stream_read_state(ssl)) {
    case SSL_STREAM_STATE_RESET_REMOTE:
      printf("Stream reset occurred\n");
      /*
       * The stream has been reset but the connection is still
       * healthy.
       */
      break;

    case SSL_STREAM_STATE_CONN_CLOSED:
      printf("Connection closed\n");
      /* Connection is already closed. */
      break;

    default:
      printf("Unknown stream failure\n");
      break;
    }
    return -1;
  default:
    printf("Unexpected error!\n");
    return -1;
  }
}

/*
 * read_ssl is a wrapper for SSL_read. It will read from the SSL session for as
 * long as ssl_check_error does not return a positive value. I.e., until there
 * is no more data to read. For our application, this should usually be once
 * only.
 */
int read_ssl(SSL *ssl, char *buf, int buf_size) {
  int ret;
  while (true) {
    ret = SSL_read(ssl, buf, buf_size);
    ret = ssl_check_error(ssl, ret);
    // In care of an issue or of success, return. Otherwise, retry.
    if (ret <= 0) {
      return ret;
    }
  }
  return 0;
}

/*
 * write_ssl is a wrapper for SSL_write. In addition, it calls ssl_check_error
 * to print useful information about issues.
 */
int write_ssl(SSL *ssl, char *buf) {
  int ret = SSL_write(ssl, buf, strlen(buf));
  return ssl_check_error(ssl, ret);
}
