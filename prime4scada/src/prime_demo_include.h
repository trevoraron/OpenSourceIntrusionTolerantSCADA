#include <stdio.h>

#include <stdlib.h>
#include <stdarg.h>

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h> 
#include <netdb.h>

#include <errno.h>

#include <math.h>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define PORT	     5555
#define MAX_MESS_LEN 8192

#define SERVERS 7
#define QUORUM 2*(SERVERS - 1)/3 + 1

#include "demo_messages.h"


