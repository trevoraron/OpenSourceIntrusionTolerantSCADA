/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/byzrep/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Prime are:
 *  Yair Amir, Jonathan Kirsch, and John Lane.
 *
 * Special thanks to Brian Coan for major contributions to the design of
 * the Prime algorithm. 
 *  	
 * Copyright (c) 2008 - 2010 
 * The Johns Hopkins University.
 * All rights reserved.
 *
 */

#ifndef	PRIME_NET_TYPES_H
#define	PRIME_NET_TYPES_H

#include "def.h"

#define SIGLEN 128 

typedef	char packet[PRIME_MAX_PACKET_SIZE];

/* The header of each message */
typedef	struct	dummy_pkt_header {
    /* The first three fields should go in front of each message */
    char     sig[SIGLEN]; /* signature of the message */
    int32u   sender_ID;   /* The ID of the sender of the packet */
    int16u   len;         /* length of the packet */
    int16u   type;        /* type of the message  */ 
} pkt_header;

#endif	/* NET_TYPES */
