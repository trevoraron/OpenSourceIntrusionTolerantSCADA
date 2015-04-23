#ifndef MESSAGES

#include <stdint.h>

typedef enum {
    INIT,
    MOVE,
    MY_STATE,
    BOUNDS,
    SPEED,
    COLOR,
    ACK,
    MAL
} message_type;

typedef enum {
    RED,
    BLUE,
    GREEN,
    YELLOW
} state_color;

typedef struct State {
    float x;
    float y;
    float direction;
    unsigned int speed;
    unsigned int x_bounds;
    unsigned int y_bounds;
    state_color color;
} State;

typedef struct Header {
    int length;
    int message_type;
} Header;

typedef struct Client_Subheader {
    int seq;
    uint16_t recv_bitmask;
    uint16_t reply_bitmask;
} Client_Subheader;

typedef struct Server_Subheader {
    int seq;
    State state;
} Server_Subheader;


/* Prints a status report of the given state */
void printState( State state );

/* Returns 1 if states are equivalent, 0 if not */
int equivalentStates( State s1, State s2 );

/* Configures TCP connections for given hosts,
    Stores sockaddr's and sockets in given buffers */
void setupHosts( int numHosts, char *hostNames[], struct sockaddr_in hosts[],
                int sockets[], fd_set *sockset );

#endif

