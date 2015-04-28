//Trevor Aron
//Socket setup functions

#include "socket_setup.h"

/*TODO: do not have browser sockets kill progam on failing, kill thread somehow */
/* Will create socket for client lib to accept browser connection */
/*port is the port to create socket on*/
/*Returns file descriptor of socket */
int browser_listen(int port) {
    int pvb_sockfd;
    struct sockaddr_in pvb_serv_addr;
    pvb_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(pvb_sockfd < 0) {
        perror("Error opening socket");
        exit(0);
    }
    bzero( (char *) &pvb_serv_addr, sizeof(pvb_serv_addr));
    pvb_serv_addr.sin_family = AF_INET;
    pvb_serv_addr.sin_addr.s_addr = INADDR_ANY;
    pvb_serv_addr.sin_port = htons(port);
    if(bind(pvb_sockfd, (struct sockaddr *) &pvb_serv_addr, sizeof(pvb_serv_addr)) < 0) {
        perror("ERROR on Binding");
        exit(0);
    }
    listen(pvb_sockfd, 5);
    return pvb_sockfd;
}

/*Get's connection from browser, returns socket to read and write to*/
/*pvb_sock_fd is the socket that's listening*/
/*Returns file descriptor of socket to read and write too*/
int browser_accept(int pvb_sock_fd) {
    int pvb_newsockfd;
    socklen_t browserlen;
    struct sockaddr_in browser_addr;

    //client = sizeof(browser_addr);
    //Accept will wait for connection
    pvb_newsockfd = accept(pvb_sock_fd, (struct sockaddr *) &browser_addr, &browserlen);
    if (pvb_newsockfd < 0) {
        perror("ERROR on accept");
        exit(0);
    }
    return pvb_newsockfd;

}

/*TODO: do not have server sockets kill progam on failing, ignore if we have > f+1 working */
/*Make server sockets */
/*server_addr is an array of servers addresses (so char * server_addr[NUM_SERVERS]) */
/*num_servers is the number of servers */
/*port is port to connect to */
/*Returns list of file descriptors to read and write too */
int server_socket(const char * server_addr, int port) {
    int pvs_sockfd;
    struct hostent * servers;
    struct sockaddr_in serv_addr;

    pvs_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(pvs_sockfd < 0) {
        perror("socket_setup: ERROR opening socket");
        exit(0);
    }
    servers = gethostbyname(server_addr);
    if(servers == NULL) {
        perror("socket_setup: Error, no such host");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    bcopy( (char *)servers->h_addr, (char *) &serv_addr.sin_addr.s_addr, servers->h_length);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if(connect(pvs_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("socket_setup: Error Connecting");
        exit(0);
    }

    return pvs_sockfd;
}

/*Read buf_size bytes into buffer */
/*Return bytes read if succesfull, return -1 if fail */
/*pass the buffer, size, and the socket to read */
int read_socket(int socket, char * buffer, int buf_size) {
    int bytes_read = 0;
    int n = 0;
    while(bytes_read < buf_size-1) {
        n = read(socket, buffer + bytes_read, 1);
        if (n < 0) {
            return -1;
        }
        if ( buffer[bytes_read] == '\n' ) break;
        bytes_read += n;
    }
    bytes_read++;
    buffer[bytes_read] = '\0';
    return bytes_read;
}
