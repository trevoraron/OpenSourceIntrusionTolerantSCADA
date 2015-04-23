#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <stdio.h>
#include "prime_demo_include.h"



void printState( State state )
{
    printf( "Current State:\n" );
    printf( "\tPosition:   (%f,%f)\n", state.x, state.y );
    printf( "\tDirection:  %f\n", state.direction );
    printf( "\tSpeed:      %d\n", state.speed );
    printf( "\tColor:      %d\n", state.color );
    printf( "\tBounds:     (%d,%d)\n", state.x_bounds, state.y_bounds );
}

int equivalentStates( State s1, State s2 )
{
    if ( s1.x == s2.x && s1.y == s2.y && s1.direction == s2.direction &&
         s1.speed == s2.speed && s1.x_bounds == s2.x_bounds &&
        s1.y_bounds == s2.y_bounds && s1.color == s2.color )
        return 1;
    return 0;
}

void setupHosts( int numHosts, char *hostNames[], struct sockaddr_in hosts[],
                int sockets[], fd_set *sockset )
{
    struct hostent  host_ent, *pHost_ent;
    char            host_name[80];
    int             ret, i;
    
    if ( sockset != NULL )FD_ZERO(sockset);
    for ( i = 0; i < numHosts; i++ ) {
        /* Create a socket (TCP) */
        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockets[i] < 0) { /* sanity check */
            perror("Net_client: socket error");
            exit(1);
        }
        if ( sockset != NULL ) FD_SET(sockets[i], sockset);
        
        /* Set family & port */
        hosts[i].sin_family = AF_INET;
        hosts[i].sin_port = htons(PORT);
        
        /* Retrieve and set host address */
        strcpy( host_name, hostNames[i] );
        printf("%s\n", host_name);
        pHost_ent = gethostbyname(host_name);
        if ( pHost_ent == NULL ) { /* sanity check */
            printf("net_client: gethostbyname error.\n");
            exit(1);
        }
        memcpy( &host_ent, pHost_ent, sizeof(host_ent) );
        memcpy( &hosts[i].sin_addr, host_ent.h_addr_list[0],
               sizeof(hosts[i].sin_addr) );
        
        /* Connect socket and host */
        ret = connect( sockets[i], (struct sockaddr *)&hosts[i],
                      sizeof(hosts[i]) );
        if (ret < 0) {
            perror("Client: could not connect to server");
            exit(1);
        } else perror("Client: connect success!");
        
    }
}





