/*
 * Adapted from:
 *  https://www.educative.io/answers/how-to-implement-udp-sockets-in-c
 *  https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 *  https://github.com/nplab/DTLS-Examples/blob/master/src/dtls_sctp_echo.c
 */
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>

#include "client.h"
#include "server.h"

/*
 * struct options is used as a return value by by parse_opts.
 */
struct options {
  bool is_client;
  char *host;
  int port;
  char *message;
  int num_messages;
  char *private_key;
  char *pem_certificate;
};

/*
 * function usage prints usage info and exits.
 */
void usage(char *program_name) {
  printf("Usage:\n");
  printf("  %s -h <socket listen address> -p <socket listen port> -k <server "
         "cert private key> -l <server cert pem>\n",
         program_name);
  printf("  %s -c -h <destination IP> -p <destination port> -i <number of "
         "messages>\n",
         program_name);
  exit(1);
}

/*
 * function parse_opts parses our options.
 * It is copied and modified from
 * https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html.
 */
struct options parse_opts(int argc, char **argv) {
  int c;

  // Setting sane defaults
  struct options o = {.num_messages = 1,
                      .private_key = (char *)malloc(PATH_MAX * sizeof(char)),
                      .pem_certificate =
                          (char *)malloc(PATH_MAX * sizeof(char))};

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));
  sprintf(o.private_key, "%s/_output/ssl.key", cwd);
  sprintf(o.pem_certificate, "%s/_output/ssl.pem", cwd);
  while ((c = getopt(argc, argv, "ch:p:m:i:k:l:")) != -1) {
    switch (c) {
    case 'c':
      o.is_client = true;
      break;
    case 'h':
      o.host = optarg;
      break;
    case 'i':
      o.num_messages = atoi(optarg);
      break;
    case 'k':
      o.private_key = optarg;
      break;
    case 'l':
      o.pem_certificate = optarg;
      break;
    case 'm':
      o.message = optarg;
      break;
    case 'p':
      o.port = atoi(optarg);
      break;
    default:
      usage(argv[0]);
    }
  }
  if (!o.host || !o.port) {
    usage(argv[0]);
  }
  return o;
}

int main(int argc, char **argv) {
  // If the client doesn't shutdown cleanly, the server might still write to the
  // broken pipe. That will lead to a SIGPIPE and the server will exit.
  // Therefore, ignore SIGPIPEs. See:
  // https://stackoverflow.com/questions/32040760/c-openssl-sigpipe-when-writing-in-closed-pipe
  sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
  struct options o = parse_opts(argc, argv);
  if (o.is_client) {
    return client(o.host, o.port, o.private_key, o.pem_certificate, o.message,
                  o.num_messages);
  }
  return server(o.host, o.port, o.private_key, o.pem_certificate);
}
