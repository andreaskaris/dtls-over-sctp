/*
 * Adapted from:
 *  https://www.educative.io/answers/how-to-implement-udp-sockets-in-c
 *   https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

bool is_client;
char *host;
int port;
char *message;

void usage(char *program_name) {
  printf("Usage:\n");
  printf("  %s -h <socket listen address> -p <socket listen port>\n",
         program_name);
  printf("  %s -c -h <destination IP> -p <destination port>\n", program_name);
}

int parse_opts(int argc, char **argv) {
  int c;

  while ((c = getopt(argc, argv, "ch:p:m:")) != -1) {
    switch (c) {
    case 'c':
      is_client = true;
      break;
    case 'h':
      host = optarg;
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

int server(char *host, int port) {
  int socket_desc;
  struct sockaddr_in server_addr, client_addr;
  char server_message[2000], client_message[2000];
  int client_struct_length = sizeof(client_addr);

  // Clean buffers:
  memset(server_message, '\0', sizeof(server_message));
  memset(client_message, '\0', sizeof(client_message));

  // Create UDP socket:
  socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (socket_desc < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  printf("Socket created successfully\n");

  // Set port and IP:
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(host);

  // Bind to the set port and IP:
  if (bind(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    printf("Couldn't bind to the port\n");
    return -1;
  }
  printf("Done with binding\n");

  printf("Listening for incoming messages...\n\n");

  while (true) {
    // Receive client's message:
    if (recvfrom(socket_desc, client_message, sizeof(client_message), 0,
                 (struct sockaddr *)&client_addr, &client_struct_length) < 0) {
      printf("Couldn't receive\n");
      return -1;
    }
    printf("Received message from IP: %s and port: %i\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    printf("Msg from client: %s\n", client_message);

    // Respond to client:
    strcpy(server_message, client_message);

    if (sendto(socket_desc, server_message, strlen(server_message), 0,
               (struct sockaddr *)&client_addr, client_struct_length) < 0) {
      printf("Can't send\n");
      return -1;
    }
  }

  // Close the socket (code will never be reached)
  close(socket_desc);
  return 0;
}

int client(char *host, int port, char *client_message) {
  int socket_desc;
  struct sockaddr_in server_addr;
  char server_message[2000];
  int server_struct_length = sizeof(server_addr);

  // Clean buffers:
  memset(server_message, '\0', sizeof(server_message));
  // memset(client_message, '\0', sizeof(client_message));

  // Create socket:
  socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (socket_desc < 0) {
    printf("Error while creating socket\n");
    return -1;
  }
  printf("Socket created successfully\n");

  // Set port and IP:
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(host);

  // Send the message to server:
  printf("Sending message to %s:%d: '%s'\n", host, port, message);
  if (sendto(socket_desc, client_message, strlen(client_message), 0,
             (struct sockaddr *)&server_addr, server_struct_length) < 0) {
    printf("Unable to send message\n");
    return -1;
  }

  printf("Receiving message from %s:%d\n", host, port);
  // Receive the server's response:
  if (recvfrom(socket_desc, server_message, sizeof(server_message), 0,
               (struct sockaddr *)&server_addr, &server_struct_length) < 0) {
    printf("Error while receiving server's msg\n");
    return -1;
  }

  printf("Server's response: %s\n", server_message);

  // Close the socket:
  close(socket_desc);

  return 0;
}

int main(int argc, char **argv) {
  if (parse_opts(argc, argv) != 0) {
    return 1;
  }
  if (is_client) {
    return client(host, port, message);
  }
  return server(host, port);
}
