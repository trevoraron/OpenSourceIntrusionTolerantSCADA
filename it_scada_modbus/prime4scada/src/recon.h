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

#ifndef PRIME_RECON_H
#define PRIME_RECON_H

#include "packets.h"
#include "data_structs.h"

typedef struct dummy_recon_part_header {
  int32u originator;
  int32u seq_num;
  int32u part_len;

  /* The erasure part follows */
} recon_part_header;

typedef struct dummy_recon_slot {
  int32u should_decode;
  int32u decoded;

  int32u num_parts_collected;
  int32u part_collected[NUM_SERVER_SLOTS];

  unsigned char parts[NUM_SERVER_SLOTS][PRIME_MAX_PACKET_SIZE];

} recon_slot;

typedef struct dummy_erasure_node {
  int32u buf[PRIME_MAX_PACKET_SIZE];
  int32u dest_bits;//Destination of the encoded message
  int32u mess_type;//Type of the encoded message
  int32u part_len; //Length of each part in bytes
  int32u mess_len; //Length of message being encoded

  /* These are the preorder identifier, used for Prime erasure-encoded
   * reconciliation */
  int32u originator;
  int32u seq_num;
  
} erasure_node;

typedef struct dummy_erasure_part_obj {
  erasure_part part;
  int32u buf[PRIME_MAX_PACKET_SIZE];
  
  int32u mess_type;
  int32u part_len;

  /* For Prime erasure-encoded reconciliation */
  int32u originator;
  int32u seq_num;

} erasure_part_obj;

void RECON_Upon_Receiving_Recon(signed_message *mess);
void RECON_Do_Recon            (ord_slot *ord_slot);
void RECON_Decode_Recon (recon_slot *slot);

void RECON_Create_Nodes_From_Messages(dll_struct *source_list,
				      dll_struct *dest_list);

void RECON_Allocate_Recon_Parts_From_Nodes(dll_struct *node_list,
					   dll_struct *dest_lists);

void RECON_Build_Recon_Packets(dll_struct *dest_lists);


#endif
