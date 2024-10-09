/*
 * Adapted from:
 *  https://www.educative.io/answers/how-to-implement-udp-sockets-in-c
 *  https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 *  https://github.com/nplab/DTLS-Examples/blob/master/src/dtls_sctp_echo.c
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct connection_info {
  int fd;
};

bool is_client;
char *host;
int port;
char *message;
int num_messages;

void usage(char *program_name) {
  printf("Usage:\n");
  printf("  %s -h <socket listen address> -p <socket listen port>\n",
         program_name);
  printf("  %s -c -h <destination IP> -p <destination port> -i <number of "
         "messages>\n",
         program_name);
}

int parse_opts(int argc, char **argv) {
  int c;

  num_messages = 1; // Setting sane defaults
  while ((c = getopt(argc, argv, "ch:p:m:i:")) != -1) {
    switch (c) {
    case 'c':
      is_client = true;
      break;
    case 'h':
      host = optarg;
      break;
    case 'i':
      num_messages = atoi(optarg);
      break;
    case 'm':
      message = optarg;
      break;
    case 'p':
      port = atoi(optarg);
      break;
    default:
      usage(argv[0]);
      return 1;
    }
  }
  if (!host || !port) {
    usage(argv[0]);
    return 1;
  }
  return 0;
}

int listen_server(char *host, int port) {
  int fd;
  struct sockaddr_in server_addr;

  // Create UDP socket:
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

  /* Specify that a maximum of 5 streams will be available per socket */
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

void *serve_connection(void *arg) {
  pthread_detach(pthread_self());

  // Create buffers for server messages.
  char server_message[2000], client_message[2000];
  memset(server_message, '\0', sizeof(server_message));
  memset(client_message, '\0', sizeof(client_message));
  struct connection_info *cinfo = (struct connection_info *)arg;
  int afd = cinfo->fd;

  while (true) {
    struct sctp_sndrcvinfo sndrcvinfo;
    int flags = 0;
    int res;

    // Receive client's message:
    res = sctp_recvmsg(afd, client_message, sizeof(client_message),
                       (struct sockaddr *)NULL, 0, &sndrcvinfo, &flags);
    if (res < 0) {
      printf("Couldn't receive\n");
      close(afd);
    } else if (res == 0) {
      printf("Peer shut down connection\n");
      break;
    }
    printf("Msg from client: %s\n", client_message);

    // Respond to client:
    strcpy(server_message, client_message);

    printf("Sending message to client: %s\n", server_message);
    if (sctp_sendmsg(afd, server_message, strlen(server_message), NULL, 0, 0, 0,
                     0, 0, 0) < 0) {
      printf("Can't send\n");
      close(afd);
    }
  }
  close(afd);
}

int server(char *host, int port) {
  pthread_t tid;
  struct sockaddr_in client_addr;
  socklen_t client_struct_length = sizeof(client_addr);
  struct connection_info *cinfo;

  // Set up the listen socket first.
  int fd = listen_server(host, port);
  if (fd < 0) {
    return -1;
  }
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
    // Serve the connection.
    if (pthread_create(&tid, NULL, serve_connection, cinfo) != 0) {
      printf("Couldn't server connection");
      close(fd);
      return -1;
    }
  }
  close(fd);
  return 0;
}

int client(char *host, int port, char *client_message, int num_messages) {
  int socket_desc;
  int res;
  struct sockaddr_in server_addr;
  char server_message[2000];
  int server_struct_length = sizeof(server_addr);
  struct sctp_sndrcvinfo sndrcvinfo;
  int flags = 0;

  // Clean buffers:
  memset(server_message, '\0', sizeof(server_message));
  // memset(client_message, '\0', sizeof(client_message));

  // Create socket:
  socket_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

  if (socket_desc < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  printf("Socket created successfully\n");

  // Set port and IP:
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(host);

  // Send connection request to server:
  if (connect(socket_desc, (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0) {
    printf("Unable to connect\n");
    return -1;
  }
  printf("Connected with server successfully\n");

  for (int i = 0; i < num_messages; i++) {
    printf("Sending message: %s\n", client_message);
    // Send the message to server:
    if (sctp_sendmsg(socket_desc, client_message, strlen(client_message), NULL,
                     0, 0, 0, 0, 0, 0) < 0) {
      printf("Unable to send message\n");
      return -1;
    }
    // Receive the server's response:
    res = sctp_recvmsg(socket_desc, server_message, sizeof(server_message),
                       (struct sockaddr *)NULL, 0, &sndrcvinfo, &flags);
    if (res < 0) {
      printf("Error while receiving server's msg\n");
      return -1;
    } else if (res == 0) {
      printf("Peer shut down connection\n");
      return 0;
    } else {
      printf("Server's response: %s\n", server_message);
    }
  }

  // Close the socket:
  close(socket_desc);

  return 0;
}

int main(int argc, char **argv) {
  if (parse_opts(argc, argv) != 0) {
    return 1;
  }
  if (is_client) {
    return client(host, port, message, num_messages);
  }
  return server(host, port);
}
