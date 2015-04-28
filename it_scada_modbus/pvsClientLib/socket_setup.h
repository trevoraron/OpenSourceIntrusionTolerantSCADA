#ifndef SOCKET_SETUP
#define SOCKET_SETUP
//Trevor Aron
//Socket Setup.h

//Includes
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>

/* Will create socket for client lib to accept browser connection */
/*port is the port to create socket on*/
/*Returns file descriptor of socket */
int browser_listen(int port);

/*Get's connection from browser, returns socket to read and write to*/
/*pvb_sock_fd is the socket that's listening*/
/*Returns file descriptor of socket to read and write too*/
int browser_accept(int pvb_sock_fd);

/*Make server sockets */
/*server_addr is an array of servers addresses (so char * server_addr[NUM_SERVERS]) */
/*num_servers is the number of servers */
/*port is port to connect to */
/*Returns list of file descriptors to read and write too */
int server_socket(const char * server_addr, int port);

/*Read buf_size bytes into buffer */
/*Return bytes read if succesfull, return -1 if fail */
/*pass the buffer, size, and the socket to read */
int read_socket(int socket, char * buffer, int buf_size);


#endif /* SOCKET_SETUP */
