//Trevor Aron
//Socket setup functions

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
    pvb_serv_addr.sin_port = htons(port)
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

    clilen = sizeof(browser_addr);
    //Accept will wait for connection
    pvb_newsockfd = accept(pvb_sockfd, (struct sockaddr *) &browser_addr, &browserlen);
    if (newsockfd < 0) {
        error("ERROR on accept");
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
int * server_sockets(char * server_addr[], int num_servers, int port) {
    int * pvs_sockfd = new int[num_servers];
    struct hostent ** servers;
    struct sockaddr_in serv_addr[] = new struct sockaddr_in[num_servers];

    for(int i = 0; i < num_servers; i++) {
        pvs_sockfd[i] = socket(AF_INET, SOCK_STREAM, 0);
        if(pvs_sockfd[i] < 0) {
            perror("ERROR opening socket");
            exit(0);
        }
        servers[i] = gethostbyname(server_addr[i]);
        if(servers[i] == NULL) {
            perror("Error, no such host");
            exit(0);
        }
        bzero((char *) &serv_addr[i], sizeof(serv_addr[i]));
        serv_addr[i].sin_family = AF_INET;
        bcopy((char *) &serv_addr[i], sizeof(serv_addr[i]));
        serv_add[i].sin_port htons(port);
        if(connect(pvs_sockfd[i], (struct sockaddr *) &serv_addr[i], sizeof(serv_addr[i])) < 0) {
            perror("Error Connecting");
            exit(0);
        }
    }
    return pvs_sockfd;
}

/*Read buf_size bytes into buffer */
/*Return bytes read if succesfull, return -1 if fail */
/*pass the buffer, size, and the socket to read */
int read_socket(char * buffer, int buf_size, int socket) {
    int bytes_read = 0;
    int n = 0;
    while(bytes_read < buf_size) {
        n = read(socket, buffer + bytes_read, buf_size - bytes_read);
        if (n < 0) {
            return -1;
        }
        bytes_read += n; 
    }
    return bytes_read;
}
