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

#ifndef PRIME_DEF_H
#define PRIME_DEF_H

/*---------------------System-wide Configuration Settings-------------------*/

/* PRIME for 7 server configuration */

/* Maximum number of tolerated faults */
#define NUM_FAULTS 1

/* Total number of servers in the system.  NUM_SERVERS must be greater
 * than or equal to (3*NUM_FAULTS + 1) */
#define NUM_SERVERS 4

/* Maximum number of clients */
#define NUM_CLIENTS 7

/* Number of bytes in a client update */
#define UPDATE_SIZE 200

/* When running a benchmark, this value indicates how many updates
 * should be executed by the servers before stopping and outputting
 * the throughput. */
#define BENCHMARK_END_RUN 1000000

/* Set this to 1 if an erasure encoding library is available and
 * integrated. By default, no erasure encoding is used and each
 * correct server that would send an erasure-encoded RECON message
 * instead sends the complete PO-Request itself (not encoded). */
#define USE_ERASURE_CODES 0

/* Variability constant K_Lat */
#define VARIABILITY_KLAT 10.0

/* Recovery: set this to 1 to allow recovery. Garbage collection
 * is disabled.  */
#define RECOVERY 1

/* Define the maximum number of data blocks that we transfer at the
 * same time. */
#define STATE_TRANSFER_MAX_LIMIT 5

/* Define the size of each data block (default: 1 megabyte). */
#define BLOCK_SIZE 1048576

/* The maximum number of bytes that are sent in each state transfer
 * message. */
#define PAYLOAD_SIZE 1024

/*--------------------Networking Settings-----------------------------------*/

#define PRIME_BOUNDED_MCAST_PORT       7100
#define PRIME_TIMELY_MCAST_PORT        7101
#define PRIME_TCP_BASE_PORT            7102
#define PRIME_BOUNDED_SERVER_BASE_PORT 7200
#define PRIME_TIMELY_SERVER_BASE_PORT  7250
#define PRIME_RECON_SERVER_BASE_PORT   7300
#define PRIME_SPINES_SERVER_BASE_PORT  7350
#define PRIME_CLIENT_BASE_PORT         7400
#define SPINES_PORT                    8100

/* Set this to 1 if IP multicast is available (i.e., when running in a
 * LAN).  Note that this option is not compatible with the
 * SET_USE_SPINES flag (see Makefile) or the
 * THROTTLE_OUTGOING_MESSAGES flag (see below). */
#define USE_IP_MULTICAST 0

/*--------------------Crypto Settings---------------------------------------*/

/* Set this to 0 to test performance when clients do not sign their
 * updates.  This approximates the performance should message
 * authentication codes be used.  NOTE: This is only for benchmarking!
 * It is not yet supported by the protocol and could be exploited by
 * faulty processors. */
#define CLIENTS_SIGN_UPDATES 0

/* In order to amortize the cost of an RSA signature over many
 * outgoing messages, each server maintains a linked lists of messages
 * that are awaiting a signature.  The server generates a single RSA
 * signature on a batch of messages (i.e., those in the list) when one
 * of two conditions occurs: (1) Enough time passes in which no
 * messages are added to the list; (2) the size of the list reaches a
 * threshold value.  SIG_SEC and SIG_USEC are the seconds and
 * microseconds of the timeout, and SIG_THRESHOLD is the threshold
 * value. */
#define SIG_SEC  0
#define SIG_USEC 1000
#define SIG_THRESHOLD 16

/* This is the maximum number of Merkle tree digests that may be
 * appended to a given message.  This value is dependent on
 * SIG_THRESHOLD: for example, setting SIG_THRESHOLD to 128 (2^7)
 * ensures that at most 7 digests will be appended.  Don't raise
 * SIG_THRESHOLD without raising this value! */
#define MAX_MERKLE_DIGESTS 4

/*---------------------------Throttling Settings----------------------------*/

/* The code can be configured so that outgoing messages are throttled,
 * where that the total sending rate for each traffic class does not
 * exceed some maximum bandwidth. Set this flag to 1 to enable
 * throttling. */
#define THROTTLE_OUTGOING_MESSAGES 0

/* These values define the maximum outgoing bandwidth of each traffic
 * class when throttling is used.  The number are in bits per second
 * (e.g., 10000000 means the outgoing bandwidth is not to exceed
 * 10Mbps). Note that in the current release, RECON messages are
 * always throttled, regardless of whether the
 * THROTTLE_OUTGOING_MESSAGES flag is set. */
#define MAX_OUTGOING_BANDWIDTH_TIMELY  100000000
#define MAX_OUTGOING_BANDWIDTH_BOUNDED 100000000
#define MAX_OUTGOING_BANDWIDTH_RECON   10000000

/* This defines the maximum burst size for the token bucket. */
#define MAX_TOKENS 900000

/* These can be used to control how frequently the throttling function
 * is called (i.e., how often we check to see if we can send new
 * messsages). */
#define THROTTLE_SEND_SEC  0
#define THROTTLE_SEND_USEC 1000

/* When throttling, we can choose to send broadcast messages out to servers
 * in order, or we can send them in a random order.  Set this to 1 to 
 * enable the randomization. */
#define RANDOMIZE_SENDING 0

/*-----------------------Periodic Sending Settings--------------------------*/

/* Certain messages can be configured to be sent periodically rather than 
 * right away.*/

/* How often do we send a Pre-Prepare? */
#define PRE_PREPARE_SEC  0
#define PRE_PREPARE_USEC 30000

/* When sending PreOrder messages periodically, how often the timeout
 * fires (i.e, how often we check to see if we can send new
 * messages) */
#define PO_PERIODICALLY_SEC  0
#define PO_PERIODICALLY_USEC 3000

/* How often do we send a Ping? */
#define SUSPECT_PING_SEC  1
#define SUSPECT_PING_USEC 0

/* How often do we send turn-around-time measure messages ? */
#define SUSPECT_TAT_MEASURE_SEC  0
#define SUSPECT_TAT_MEASURE_USEC 500000

#define SUSPECT_TAT_UB_SEC  1
#define SUSPECT_TAT_UB_USEC 0

#define SUSPECT_LEADER_SEC  0
#define SUSPECT_LEADER_USEC 500000

/* These flags control which PO messages are sent periodically.  Set
 * an entry to 0 to have it NOT be sent periodically. */ 
#define SEND_PO_REQUESTS_PERIODICALLY  1
#define SEND_PO_ACKS_PERIODICALLY      1 
#define SEND_PO_ARU_PERIODICALLY       1
#define SEND_PROOF_MATRIX_PERIODICALLY 1

/* When the PO messages are sent periodically, this is how many
 * timeouts need to fire before we send each one.  For example, if 
 * PO_REQUEST_PERIOD = 3, then we send a PO_Request no more frequently
 * than once every (PO_PERIODICALLY_USEC * 3) = 9 ms. */
#define PO_REQUEST_PERIOD             3
#define PO_ACK_PERIOD                 3
#define PO_ARU_PERIOD                 3
#define PROOF_MATRIX_PERIOD           3

/*-----------------------Attack Settings-----------------------------------*/

/* Set this to 1 to mount the leader's delay attack.  The leader
 * ignores PO-ARU messages, only handles Proof-Matrix messages when it
 * needs to (to avoid being suspected), and only sends the Pre-Prepare
 * to server 2. DELAY_TARGET is how long a Proof-Matrix sits at the
 * leader before it is processed.  Note that in this version of the
 * attack, the leader does not explicitly adjust the rate at which it
 * sends Pre-Prepare messages; it simply adjusts what PO-ARU messages
 * (from the Proof Matrix messages it receives) must be included in
 * the next Pre-Prepare. Note also that this is more generous to the
 * malicious leader than would be allowed in a real implementation:
 * since the leader only sends Pre-Prepares periodically, if it
 * decides not to send a Pre-Prepare now, it needs to wait another
 * timeout before trying again, and so the delays can sum. A more
 * precise attack would compute the minimum time in the future that
 * the leader needs to send the next Pre-Prepare as a function of what
 * Proof-Matrix messages it has received. */
#define DELAY_ATTACK 0
#define DELAY_TARGET 0.020

/* Set this to 1 to mount the reconciliation attack described in the paper.
 * Faulty servers only acknowledge each other's messages and don't send
 * their PO-Requests to f correct servers. */
#define RECON_ATTACK 0

/*----------------------- Internally used defines-------------------------- */
#define FALSE                      0
#define TRUE                       1

#define NET_CLIENT_PROGRAM_TYPE    1
#define NET_SERVER_PROGRAM_TYPE    2

#define BROADCAST                  0

//JCS: I increased the max packet size so that PC_Set messages could be sent in a single UDP message. We may want to change this if doing WAN experiments, if network can't handle such big UDP packets, or if using more than 4 servers. If so, will most likely need to implement a service that runs right on top of UDP that does something like fragmentation.

#define PRIME_MAX_PACKET_SIZE      5000 //2500 1472 2000 
#define NUM_SERVER_SLOTS           (NUM_SERVERS+1)

/* We store two additional pieces of information, each an integer, in
 * the util_dll structures.  The first is referred to in the code as
 * dest_bits: the integer is a bitmap containing the destinations for
 * the given signed message.  The second is the timeliness of the
 * message (i.e., what traffic class is it in).*/
#define DEST       0
#define TIMELINESS 1

/* Traffic classes.  Note that these can be set to identical values in
 * order to create fewer traffic classes (e.g., making BOUNDED AND
 * RECON the same number will put them both onto the same queue. */
#define NUM_TRAFFIC_CLASSES        3
#define TIMELY_TRAFFIC_CLASS       0
#define BOUNDED_TRAFFIC_CLASS      1
#define RECON_TRAFFIC_CLASS        2

/* The maximum number of PO-Acks that can fit in a single packet, as a 
 * function of the maximum packet size and the number of Merkle tree 
 * digests that may be appended to the message. */
#define MAX_ACK_PARTS  (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - sizeof(po_ack_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / sizeof(po_ack_part)

/* After reading an event, we poll the socket to see if there are
 * more.  This lets us do as much reading as possible.  The threshold
 * below adjusts the maximum number of messages that will be read
 * during any one poll. If no message is available, we stop polling
 * immediately and return to the main event loop. See util/events.c */
#define POLL_NON_LOW_PRIORITY_THRESHOLD 30000

#endif
