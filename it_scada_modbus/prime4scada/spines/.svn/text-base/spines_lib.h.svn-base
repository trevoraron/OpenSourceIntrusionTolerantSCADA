/*
 * Spines.
 *
 * The contents of this file are subject to the Spines Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spines.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Creators of Spines are:
 *  Yair Amir, Claudiu Danilov and John Schultz.
 *
 * Copyright (c) 2003 - 2013 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera
 *
 */

#ifndef SPINES_LIB_H
#define SPINES_LIB_H

#ifndef ARCH_PC_WIN95
#include <sys/types.h>
#include <sys/socket.h>
#endif

#ifdef ARCH_PC_WIN95
#include <winsock2.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ARCH_SPARC_SUNOS
#define socklen_t size_t
#endif

#ifdef ARCH_SPARC_SOLARIS
#define socklen_t size_t
#endif



#define     UDP_LINKS               0x00000000
#define     RELIABLE_LINKS          0x00000001
#define     SOFT_REALTIME_LINKS     0x00000002
#define     RESERVED_LINKS1         0x00000003 /* MN */
#define     RESERVED_LINKS2         0x00000004 /* SC2 */
#define     TCP_IP_LINKS            0x00000005 
#define     INTRUSION_TOL_LINKS     0x00000008 /* DT */
#define     RESERVED_LINKS_BITS     0x0000000f

#define     UDP_CONNECT             0x00000010

#define MIN_WEIGHT_ROUTING          0x00000000
#define BEST_EFFORT_FLOOD_ROUTING   0x00000100
#define RELIABLE_FLOOD_ROUTING      0x00000200
#define RESERVED_ROUTING_BITS       0x00000f00
#define ROUTING_BITS_SHIFT          8

#define     SEND_GROUP              0x1000
#define     RECV_GROUP              0x2000
#define     SENDRECV_GROUP          0x3000

#define     AF_SPINES               AF_INET
#define     PF_SPINES               AF_SPINES

#define     SPINES_ADD_MEMBERSHIP   IP_ADD_MEMBERSHIP
#define     SPINES_DROP_MEMBERSHIP  IP_DROP_MEMBERSHIP
#define     SPINES_MULTICAST_LOOP   IP_MULTICAST_LOOP
#define     SPINES_IP_TTL           IP_TTL
#define     SPINES_IP_MULTICAST_TTL IP_MULTICAST_TTL
#define     SPINES_ADD_NEIGHBOR     51 

#define     SPINES_TRACEROUTE       61
#define     SPINES_EDISTANCE        62
#define     SPINES_MEMBERSHIP       63

#define     SPINES_SET_PRIORITY     71
#define     SPINES_SET_EXPIRATION   72
#define     SPINES_DISJOINT_PATHS   73

#define     DEFAULT_SPINES_PORT     8100

#define     SP_ERROR_VERSION_MISMATCH   7845
#define     SP_ERROR_LIB_ALREADY_INITED 7846
#define     SP_ERROR_INPUT_ERR          7847
#define     SP_ERROR_DAEMON_COMM_ERR    7848
#define     SP_ERROR_MAX_CONNECTIONS    7849

#define     MAX_COUNT               64

/* IP Address Class Check */
#ifndef Is_mcast_addr
#  define Is_mcast_addr(x) (((x) & 0xF0000000) == 0xE0000000)
#  define Is_acast_addr(x) (((x) & 0xF0000000) == 0xF0000000)
#  define Is_node_addr(x)  (!Is_mcast_addr(x) && !Is_acast_addr(x))
#endif

typedef struct Lib_Client_d {
    int tcp_sk;
    int udp_sk;
    int type;
    int endianess_type;
    int sess_id;
    int rnd_num;
    int srv_addr;       /* stored in host byte order */
    int srv_port;
    int protocol;
    int my_addr;
    int my_port;
    int connect_addr;
    int connect_port;
    int connect_flag;
    int virtual_local_port;  /* stored in host byte order */
    int ip_ttl;              /* ttl to stamp all unicast "DATA" UDP packets */ 
    int mcast_ttl;           /* ttl to stamp all multicast "DATA" UDP packets */
    int routing;
} Lib_Client;

typedef struct spines_trace_d {
    int count;
    long address[MAX_COUNT];
    int distance[MAX_COUNT];
    int cost[MAX_COUNT];
} spines_trace;

typedef struct spines_nettime_d {
    int sec;
    int usec;
} spines_nettime;

/* PUBLIC INTERFACE */

int  spines_init(const struct sockaddr *serv_addr);
int  spines_socket(int domain, int type, int protocol, 
		   const struct sockaddr *serv_addr);
void spines_close(int s);
int  spines_bind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
int  spines_send(int s, const void *msg, size_t len, int flags);
int  spines_recv(int s, void *buf, size_t len, int flags);
int  spines_listen(int s, int backlog);
int  spines_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int  spines_sendto(int s, const void *msg, size_t len, int flags, 
		   const struct sockaddr *to, socklen_t tolen);
int  spines_recvfrom(int s, void *buf, size_t len, int flags, 
		     struct sockaddr *from, socklen_t *fromlen);
int  spines_connect(int  sockfd,  const  struct sockaddr *serv_addr, 
                    socklen_t addrlen);
int  spines_setsockopt(int s, int  level,  int  optname,  void  *optval,
		       socklen_t optlen);
int  spines_ioctl(int s, int  level,  int  optname,  void  *optval,
		  socklen_t optlen);
int  spines_getsockname(int sk, struct sockaddr *name, socklen_t *nlen);

/* Enhanced recvfrom function that returns the destination address -- this
 * corresponds to the multicast group to which the packet was sent This is a
 * hack just to get things working April 24, 2009. */
int  spines_recvfrom_dest(int s, void *buf, size_t len, int flags, 
		     struct sockaddr *from, socklen_t *fromlen, unsigned int *dest );

/* END PUBLIC INTERFACE */

int spines_flood_send(int sockfd, int address, int port, int rate, int size, int num_pkt);
int spines_flood_recv(int sockfd, char *filename, int namelen);
int spines_socket_internal(int domain, int type, int protocol, 
                           const struct sockaddr *serv_addr, int *udp_sk, int *tcp_sk);
int spines_sendto_internal(int s, const void *msg, size_t len, int flags, 
                           const struct sockaddr *to, socklen_t tolen, int force_tcp);
int spines_recvfrom_internal(int s, void *buf, size_t len, int flags, 
                             struct sockaddr *from, socklen_t *fromlen, int force_tcp, unsigned int *dest);

int spines_setlink(int sk, int remote_interf_id, int local_interf_id,
                   int bandwidth, int latency, float loss, float burst);

int spines_get_client(int sk);

#ifdef __cplusplus
}
#endif

#endif
