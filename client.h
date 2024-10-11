#ifndef CLIENT_H
#define CLIENT_H

/*
 * client implements the client. It takes a destination host and port number as
 * well as the client private key and certificate. It then establishes a
 * connection to the server, negotiates DTLS and sends a message num_messages
 * times.
 */
int client(char *host, int port, char *client_private_key,
           char *client_certificate, char *client_message, int num_messages);

#endif