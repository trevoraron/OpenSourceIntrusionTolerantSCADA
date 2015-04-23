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

#ifndef PRIME_DATA_STRUCTS_H
#define PRIME_DATA_STRUCTS_H

#include <stdio.h>
#include "def.h"
#include "arch.h"
#include "spu_events.h"
#include "stdutil/stdhash.h"
#include "openssl_rsa.h"
#include "stopwatch.h"
#include "util_dll.h"
#include "packets.h"

#define MAX_PRE_PREPARE_PARTS 2

/* Public Functions */
void DAT_Initialize(void); 

typedef struct server_variables_dummy {
  int32u My_Server_ID;
  int32u Faults;
} server_variables;

typedef struct network_variables_dummy {
  int32    My_Address;
  int32u   program_type;

  /* Client socket descriptor handling */
  int32    sd;                       /* To respond to clients              */
  int32    listen_sd;                /* To listen for incoming connections */
  int32    client_sd[NUM_CLIENTS+1]; /* Which sd is for which client       */

  /* Stores the IP address of each server, read from configuration file  */
  int32 server_address[NUM_SERVER_SLOTS];

#ifdef SET_USE_SPINES
  channel  Spines_Channel;
  int32 server_address_spines[NUM_SERVER_SLOTS];
#endif

  int16u  Client_Port;

  int16u  Bounded_Port;
  int32   Bounded_Channel;
  int32   Bounded_Mcast_Address;
  int16u  Bounded_Mcast_Port;
  channel Bounded_Mcast_Channel;

  int16u  Timely_Port;
  int32   Timely_Channel;
  int32   Timely_Mcast_Address;
  int16u  Timely_Mcast_Port;
  channel Timely_Mcast_Channel;

  int16u  Recon_Port;
  channel Recon_Channel;

  dll_struct pending_messages_dll[NUM_TRAFFIC_CLASSES];
  double tokens[NUM_TRAFFIC_CLASSES];
  util_stopwatch sw[NUM_TRAFFIC_CLASSES];

} network_variables;

typedef struct dummy_net_struct {
  signed_message *mess;
  int32u server_id;
  int32u site_id;

  int32u dest_bits;
  int32u num_remaining_destinations;
  int32u destinations[NUM_SERVER_SLOTS];

  int32u timeliness;

} net_struct;

typedef struct dummy_benchmark_struct {
  int32u updates_executed;

  int32u num_po_requests_sent;
  int32u total_updates_requested;

  int32u num_flooded_pre_prepares;

  int32u num_po_acks_sent;
  int32u num_acks;
  double total_bits_sent[3];
  int32u clock_started;

  double bits[25];

  int32u num_signatures;
  int32u total_signed_messages;
  int32u max_signature_batch_size;
  int32u signature_types[LAST_MESSAGE_TYPE];

  double num_throttle_sends;

  util_stopwatch test_stopwatch;
  util_stopwatch sw;
  util_stopwatch message_validation;
  util_stopwatch state_transfer;
  util_stopwatch total_test_sw;

  FILE *state_machine_fp;

} benchmark_struct;

/* Pre-Order Data structures*/
typedef struct dummy_po_data_struct {

  /* For each server, what is the last one I've sent a PO-Ack for */
  int32u  max_acked[NUM_SERVER_SLOTS];

  /* For each server, I've collected PO-Requests contiguously up to
   * this sequence number */
  int32u  aru[NUM_SERVER_SLOTS];

  /* For each (i, j), I know that i has acknowledged (cumulatively or
   * regularly) having PO_Requests through [i][j] from j */
  int32u  cum_max_acked[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];

  int32u  cum_aru[NUM_SERVER_SLOTS];
  stdhash History[NUM_SERVER_SLOTS];
  int32u  max_num_sent_in_proof[NUM_SERVER_SLOTS];
  
  /* The last PO-ARU I've received from each server */
  po_aru_signed_message cum_acks[NUM_SERVER_SLOTS];

  /* Preorder sequence number, incremented each time I sent a Local
   * PO_Request*/
  int32u po_seq_num;

  /* PO-ARU number, incremented each time I send a Local PO-ARU */
  int32u po_aru_num;

  /* For each server i, I've executed preordered events through 
   * (i, white_line[i]) */
  int32u white_line[NUM_SERVER_SLOTS];

  /* For each client, the last executed update. It is used to 
   * avoid duplicates. */
  int32u client_ts[NUM_CLIENTS + 1];

  /* Timers */
  util_stopwatch po_request_sw;
  util_stopwatch po_ack_sw;
  util_stopwatch po_aru_sw;
  util_stopwatch proof_matrix_sw;

  /* Local Token rate limiter */
  int32 tokens;
  util_stopwatch token_stopwatch;

  /* Queue of PO-Request and PO-Proof messages waiting to be sent */
  dll_struct po_request_dll;
  dll_struct proof_matrix_dll;

  /* If we try to execute a local commit but don't yet have all of
   * the PO-Requests that become eligible, we need to hold off on
   * executing.  When we hold off b/c of PO-Request (i, j), we'll
   * store a pointer to the ord_slot in Pending_Execution[i] --> j */
  stdhash Pending_Execution[NUM_SERVER_SLOTS];

  /* Map[i] stores local_recon slots for preorder ids (i, j) */
  stdhash Recon_History[NUM_SERVER_SLOTS];

  /* (i, j) = k means: I have sent a recon message to server i for a
   * po_request (j, k) */
  int32u Recon_Max_Sent[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];

} po_data_struct;

typedef struct dummy_po_slot {
  /* The preorder sequence number */
  int32u seq_num;           
  
  /* A flag that indicates if the po_slot has been executed */
  int32u executed;

  /* A copy of the request message */
  signed_message *po_request; 

  /* A copy of received PO-ACKs for recovery */
  signed_message *po_ack[NUM_SERVER_SLOTS];

  /* Tracks the acks received from each server */
  int32u ack_received[NUM_SERVER_SLOTS]; 
  int32u ack_count;
  
  /* Used to keep track of how many updates are packed into this po_request */
  int32u num_events;
} po_slot;

/* Ordering data structure slot */
typedef struct dummy_ord_slot {
  /* seq number of this slot */
  int32u seq_num;		
  int32u view;

  /* servers' aru at this execution point */
  int32u aru_at_this_point[NUM_SERVER_SLOTS];

  /* current pre prepare */
  signed_message *pre_prepare;
  int32u pre_prepare_parts[MAX_PRE_PREPARE_PARTS+1];
  int32u total_parts;
  int32u num_parts_collected;
  int32u collected_all_parts;
  int32u should_handle_complete_pre_prepare;
  complete_pre_prepare_message complete_pre_prepare;

  /* Flag: did we forward the Pre-Prepare part? */
  int32u forwarded_pre_prepare_parts[MAX_PRE_PREPARE_PARTS+1];
  int32u num_forwarded_parts;

  /* current prepares */
  signed_message* prepare[NUM_SERVER_SLOTS]; 
  int32u ordered;
  int32u bound;
  int32u executed;

  /* current commits */
  signed_message* commit[NUM_SERVER_SLOTS];        

  /* When a Prepare certificate is ready, we mark the flag here.  The
   * dispatcher sees this and sends a commit, then sets the flag so we 
   * only send the commit once. */
  int32u prepare_certificate_ready;
  int32u sent_commit;

  /* Flag to signal if a commit certificate should be executed */
  int32u execute_commit;	

  /* Last prepare certificate */
  prepare_certificate_struct prepare_certificate;	
  
  /* Commit certificate */
  commit_certificate_struct commit_certificate;	

  /* If we commit the slot before we're ready to execute, this tells
   * us how many missing po-requests we need to collect before we can
   * execute. */
  int32u num_remaining_for_execution;

  /* Have we already reconciled on this slot? */
  int32u reconciled;

} ord_slot;

typedef struct dummy_ordering_data_struct {
  /* The local ARU. */
  int32u ARU;

  int32u server_aru[NUM_SERVER_SLOTS];
  
  /* Number of events we've ordered */
  int32u events_ordered;

  /* The next sequence number to assign */
  int32u seq;

  /* The Ordering History, which stores ordering_slots */
  stdhash History;

  util_stopwatch pre_prepare_sw;

  /* To store ord slots that are globally ordered but not yet ready to
   * be globally executed. */
  stdhash Pending_Execution;

  int32u forwarding_white_line;
  int32u recon_white_line;

} ordering_data_struct;


/* data structure for the suspect leader protocol */

typedef struct dummy_suspect_leader_data_struct {

    double tats_if_leader[NUM_SERVER_SLOTS];
    double tat_leader_ubs[NUM_SERVER_SLOTS];
    double reported_tats[NUM_SERVER_SLOTS];

    double tat_leader;
    double tat_acceptable;

    int32u ping_seq_num;

    util_stopwatch rtt;

    util_stopwatch turnaround_time;
    double max_tat;
    int32u turnaround_on;

    /* I've essentially merged the suspect leader protocol and the leader
	election protocol together into the same code. Below are the 
	data structures for it */

    signed_message *new_leader[NUM_SERVER_SLOTS];
    int32u new_leader_count;
    int32u sent_proof;

} suspect_leader_data_struct;

/* Data struct for the reliable broadcast protocol */
/* This protocol assumes a correct node only sends one message at a time */

typedef struct dummy_reliable_broadcast_data_struct {
    int32u seq_num[NUM_SERVER_SLOTS];
    //signed_message *rb_init[NUM_SERVER_SLOTS];
    int32u rb_echo[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];
    int32u rb_ready[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];
    int32u rb_step[NUM_SERVER_SLOTS];
    int32u sent_message;

} reliable_broadcast_data_struct;

/* Data struct for view change protocol */

typedef struct dummy_view_change_struct {
  int32u numSeq;
  int32u curSeq;
  stdit seq_it;
  int32u received_report[NUM_SERVER_SLOTS];
  report_message report[NUM_SERVER_SLOTS];
  int32u executeTo;
  dll_struct my_pc_set;
  dll_struct pc_set[NUM_SERVER_SLOTS];

  int32u complete_state; //bitmap of machine ids
  int32u sent_vc_list;
  int32u received_vc_list[NUM_SERVER_SLOTS];
  vc_list_message vc_list[NUM_SERVER_SLOTS];
 
  int32u sent_vc_partial_sig[NUM_SERVER_SLOTS];
  int32u received_vc_partial_sig[NUM_SERVER_SLOTS][NUM_SERVERS];
  vc_partial_sig_message vc_partial_sig[NUM_SERVER_SLOTS][NUM_SERVERS];

  int32u sent_replay;
  int32u sent_prepare;
  signed_message* replay;
  signed_message* replay_prepare[NUM_SERVER_SLOTS];
  int32u prepare_ready;
  signed_message* replay_commit[NUM_SERVER_SLOTS];
  int32u sent_commit;
  int32u commit_ready;
  int32u highest_server_id;

} view_change_struct;

typedef struct dummy_signature_data_struct {
  dll_struct pending_messages_dll;

  int32u seq_num;

  /* How many messages we've read without generating a signature.  If
   * this gets above a certain threshold, call the Sig signing
   * function immediately. */
  int32u num_consecutive_messages_read;

  sp_time sig_time;

} signature_data_struct;

typedef struct dummy_catch_up_struct {
  int32u seq_num[NUM_SERVERS + 1];
  int32u view[NUM_SERVER_SLOTS];
  int32u aru[NUM_SERVER_SLOTS];
  int32u temp_aru[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];
  int32u replies;
  int32u complete;
  int32u rec_point;
  int32u last_buffered_mess;
} catch_up_struct;

typedef struct dummy_state_data_struct {
  int32u checkpoint_id;
  int32u num_of_blocks;
  int32u parts_per_data_block;
  off_t state_size;
  byte digest[DIGEST_SIZE];
  byte received_digest[DIGEST_SIZE];
  signed_message *reply[NUM_SERVERS + 1];
  int32u retrieved_data_blocks;
  int32u next_data_block;
  int32u number_of_replies;
  int32u digest_ready;
  int32u state_ready;
  int32u last_written_block;
  int32u transferring;
  FILE *fp;
} state_data_struct;

/* This stores all of the server's state, including Preordering
 * and Ordering state. */
typedef struct dummy_server_data_struct {
  /* The view number.  For the tests, should always be 1. */
  int View;
  int32u preinstall;

  int32u recovery_in_progress;
  int32u buffering_during_recovery;
  int32u execute_batch;

  /* The Pre-Order data structure */
  po_data_struct PO;
  
  /* The Ordering data structure */
  ordering_data_struct ORD;

  suspect_leader_data_struct SUS;

  reliable_broadcast_data_struct REL;

  view_change_struct VIEW;

  signature_data_struct SIG;

  /* The proactive recovery data structures */
  catch_up_struct CAT;
  state_data_struct STATE;

} server_data_struct;


/**
 * Data structure for proactive recovery
 */

typedef struct dummy_retrieved_cert {
  int32u seq_num;
  int32u server_id;
  int32u received_replies;
  int32u validating;
  int32u bitmask;
  int32u val_attempt;
  int32u certificate_ready;
  signed_message *reply[NUM_SERVERS];
} retrieved_cert;

typedef struct dummy_data_block {
  int32u block_number;
  int32u state_sender_h;
  int32u digest_sender_h;
  stdhash parts;
  int32u current_part;
  char *data_buffer;
  signed_message *digest_reply[NUM_SERVERS + 1];
  byte block_digest[DIGEST_SIZE];
  byte my_digest[DIGEST_SIZE];
  int32u received_digest_replies;
  int32u digest_ready;
  int32u valid_block;
  int32u block_ready;
  int32u compromised_block;
  int32u block_size;
} data_block;

typedef struct dummy_db_state_part {
  int32u checkpoint_id;
  int32u part;
  signed_message *state_part;
} db_state_part;
#endif
