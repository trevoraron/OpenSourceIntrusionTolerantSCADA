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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "recon.h"
#include "spu_alarm.h"
#include "spu_memory.h"
#include "utility.h"
#include "pre_order.h"
#include "erasure.h"
#include "recon.h"
#include "order.h"
#include "apply.h"
#include "signature.h"
#include "dispatcher.h"

extern server_variables   VAR;
extern server_data_struct DATA;

int32u RECON_Do_I_Send_Erasure(int32u machine_id, 
			       po_aru_signed_message *cum_acks);
void RECON_Update_Recon_White_Line (void);

void RECON_Upon_Receiving_Recon (signed_message *recon)
{
  int32u i;
  recon_message *r;
  recon_part_header *rph;
  erasure_part *part;
  recon_slot *slot;
  char *p;

  r = (recon_message *)(recon + 1);
  p = (char *)(r + 1);

  for(i = 0; i < r->num_parts; i++) {

    rph  = (recon_part_header *)p;
    part = (erasure_part *)(rph + 1);
    
    slot = UTIL_Get_Recon_Slot_If_Exists(rph->originator, rph->seq_num);

    if(slot && slot->should_decode) {
      Alarm(DEBUG, "Want to decode %d %d\n", rph->originator, rph->seq_num);
      
      /* Make sure we need this one */
      assert(DATA.PO.white_line[rph->originator] < rph->seq_num);
      Alarm(DEBUG, "DATA.PO.aru[%d] = %d\n",
            rph->originator, DATA.PO.aru[rph->originator]);

      slot->should_decode = 0;
      slot->decoded       = 1;

      RECON_Decode_Recon(slot);
      /* Garbage collection is done at local execution time */
    }
    
    /* Move on to the next one */
    p = (char *)part;
    p += rph->part_len;
  }
}

void RECON_Do_Recon (ord_slot *o_slot)
{
  complete_pre_prepare_message *pp;
  complete_pre_prepare_message *prev_pp;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  signed_message *req;
  po_request_message *rs;
  int32u gseq, i, j, k, should_send;
  int32u prev_pop[NUM_SERVER_SLOTS];
  int32u cur_pop[NUM_SERVER_SLOTS];
  int32u dest_bits, added_to_queue;
  dll_struct message_list, node_list;
  dll_struct erasure_server_dll[NUM_SERVER_SLOTS];

  /* If we've already reconciled this slot, don't do it again */
  if(o_slot->reconciled)
    return;

  /* We need to have a complete Pre-Prepare for this slot */
  if(o_slot->collected_all_parts == 0)
    return;
  
  pp   = &o_slot->complete_pre_prepare;
  gseq = pp->seq_num;
  
  /* First check to see if we've locally executed the previous global
   * sequence number. */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);
  
  /* The previous slot is allowed to be NULL only if this is the first seq.
   * Otherwise, it means we can't have a complete Pre-Prepare for that one
   * yet and should return. */
  if(prev_ord_slot == NULL && gseq != 1)
    return;
  
  /* We have a slot for the previous seq but not a complete Pre-Prepare */
  if(prev_ord_slot && prev_ord_slot->collected_all_parts == 0)
    return;

  /*-----If we get here, we're good to reconcile.-------*/

  /* See which PO-Requests are now eligible for execution. */
  if(prev_ord_slot == NULL) {
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = 0;
  }
  else {
    prev_pp = &prev_ord_slot->complete_pre_prepare;
    
    /* Set up the Prev_pop array */
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = PRE_ORDER_Proof_ARU(i, prev_pp->cum_acks);
  }
  
  /* Set up the current array */
  for(i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = PRE_ORDER_Proof_ARU(i, pp->cum_acks);
  
  UTIL_DLL_Initialize(&message_list);
  for(i = 1; i <= NUM_SERVERS; i++) {
    for(j = prev_pop[i] + 1; j <= cur_pop[i]; j++) {
      
      p_slot = UTIL_Get_PO_Slot_If_Exists(i, j);

      /* If I have this po_slot and its po_request, see if I'm supposed
       * to send a reconciliation message for it. */
      if(p_slot && (req = p_slot->po_request) != NULL) {

	rs = (po_request_message *)(req + 1);

	dest_bits      = 0;
	added_to_queue = 0;

	should_send = 
	  RECON_Do_I_Send_Erasure(req->machine_id, pp->cum_acks);

	if(should_send) {

	  for(k = 1; k <= NUM_SERVERS; k++) {
	    
	    if(DATA.PO.cum_max_acked[k][req->machine_id] < rs->seq_num &&
	       k != req->machine_id && 
	       DATA.PO.Recon_Max_Sent[k][i] < rs->seq_num) {	      

	      if(rs->seq_num % 1 == 0 && !UTIL_I_Am_Faulty())
		Alarm(DEBUG,"RECON: Server %d found %d needs (%d, %d) "
		      "and will send\n", VAR.My_Server_ID, k, i, j); 
	      Alarm(DEBUG, "LastPOARU[%d][%d] = %d, rs->seq_num = %d\n",
		    k, req->machine_id, 
		    DATA.PO.cum_max_acked[k][req->machine_id], 
		    rs->seq_num);
	      
	      /* Add the message to the list only the first time
	       * someone needs it */
	      if(!added_to_queue) {

		if(USE_ERASURE_CODES == 0)  {
		  /* If we're throttling, add the PO-Request to the queue of
		   * pending messages directly, without signing it first. */

		  if(THROTTLE_OUTGOING_MESSAGES) {
		    int32u dest_bits = 0;
		    UTIL_Bitmap_Set(&dest_bits, k);
		    if(!UTIL_I_Am_Faulty()) {
		      NET_Add_To_Pending_Messages(req, dest_bits, 
						  UTIL_Get_Timeliness(RECON));
		    }
		  }
		  else {
		    /* If we're not throttling, just send it immediately */
		    if(!UTIL_I_Am_Faulty())
		      UTIL_Send_To_Server(req, k);
		  }
		}
		else { /* We're using erasure codes! */
		  /* We're using erasure codes!  Add request to the queue of 
		   * messages that need to be encoded.*/
		  UTIL_DLL_Add_Data(&message_list, req);
		  added_to_queue = 1;
		  Alarm(DEBUG, "Added (%d, %d) to message list\n", i, j);
		  
		  DATA.PO.Recon_Max_Sent[k][i] = j;
		}
	      }	      

	      /* Mark k as the server that needs it */
	      UTIL_Bitmap_Set(&dest_bits, k);
	      UTIL_DLL_Set_Last_Extra(&message_list, DEST, dest_bits);
	    }
	  }
	}
      }
    }
  }

  /* Mark that we've reconciled this slot and try to update the white
   * line. Also try to garbage collect the ord_slot. */
  o_slot->reconciled = 1;
  RECON_Update_Recon_White_Line();
  ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq);

  /* Return if nothing to do */
  if(UTIL_DLL_Is_Empty(&message_list))
    return;

  /* We now have a (potentially empty) message list containing the messages
   * I need to encode, along with their destinations. Encode each message
   * once (regardless of how many destinations there are). */
  UTIL_DLL_Initialize(&node_list);
  RECON_Create_Nodes_From_Messages(&message_list, &node_list);

  /* Now allocate the parts to each server that it needs */
  for(i = 1; i <= NUM_SERVERS; i++)
    UTIL_DLL_Initialize(&erasure_server_dll[i]);

  RECON_Allocate_Recon_Parts_From_Nodes(&node_list, erasure_server_dll);
  
  /* Now build the packets for each server and add them to list of messages
   * awaiting a signature. */
  RECON_Build_Recon_Packets(erasure_server_dll);
}

int32u RECON_Do_I_Send_Erasure(int32u machine_id,
			       po_aru_signed_message *cum_acks)
{
  int32u s;
  int32u cack[ NUM_SERVER_SLOTS ];
  int32u scack[ NUM_SERVER_SLOTS ];
  bool could_send[ NUM_SERVER_SLOTS ];
  int32u sender_count;
  
  for(s = 1; s <= NUM_SERVERS; s++) {
    cack[s]  = cum_acks[s-1].cum_ack.ack_for_server[machine_id-1];
    scack[s] = cum_acks[s-1].cum_ack.ack_for_server[machine_id-1];
  }
  
  /* sort the values */
  qsort((void*)(scack+1), NUM_SERVERS, sizeof(int32u), intcmp);
  
  for(s = 1; s <= NUM_SERVERS; s++)
    Alarm(DEBUG," (%d,%d) ", s, cack[s]);  
  Alarm(DEBUG,"\n");
  
  for(s = 1; s <= NUM_SERVERS; s++) 
    could_send[s] = (cack[s] >= scack[VAR.Faults + 1]) ? TRUE : FALSE;
  
  sender_count = 0;

  if(could_send[VAR.My_Server_ID] == TRUE) {
    for(s = 1; s <= NUM_SERVERS; s++) {
      if(could_send[s] == TRUE) 
	sender_count++;
      if(s == VAR.My_Server_ID) {

#if 0
	if(s == machine_id) {
	  int i;

	  Alarm(PRINT, "Cack: [ ");
	  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++)
	    Alarm(PRINT, "%d ", cack[i]);
	  Alarm(PRINT, "]\n");

	  Alarm(PRINT, "Scack: [ ");
	  for(i = 1; i <= NUM_SERVERS_IN_SITE; i++)
	    Alarm(PRINT, "%d ", scack[i]);
	  Alarm(PRINT, "]\n");
	  
	  //assert(0);
	}
#endif
	
	return TRUE;
      }

      if(sender_count == (2 * VAR.Faults + 1))
	return FALSE;
    }
  }
  
  return FALSE;
}

void RECON_Update_Recon_White_Line()
{
  ord_slot *slot;
  int32u seq;

  while(1) {
    
    seq = DATA.ORD.recon_white_line + 1;

    slot = UTIL_Get_ORD_Slot_If_Exists(seq);
    if(slot != NULL && slot->reconciled) {
      ORDER_Attempt_To_Garbage_Collect_ORD_Slot(seq);
      DATA.ORD.recon_white_line++;
    }
    else
      break;
  }
}

void RECON_Decode_Recon(recon_slot *slot)
{
  signed_message *mess;
  erasure_part *part;
  int32u i, message_len, ret;
  int32u mpackets, rpackets;
  int32u initialized;
  po_request_message *req;
  
  initialized = 0;
  message_len = 0;
  ERASURE_Clear();
  
  for(i = 1; i <= NUM_SERVERS; i++) {
    /* We have a part from this server.  */
    if(slot->part_collected[i]) {
      
      part = (erasure_part *)slot->parts[i];
      
      /* If we have not yet initialized the decoding, do so */
      if(initialized == 0) {
	initialized = 1;
	
	assert(part->mess_len != 0);
	message_len = part->mess_len;
	Alarm(DEBUG, "Initialized decoding with len %d\n", message_len);
	
	/* Message was encoded into 3f+1 parts, f+1 of which are
	   needed to decode. */
	mpackets = (NUM_FAULTS+1);
	rpackets = (2 * NUM_FAULTS);
	
	ERASURE_Initialize_Decoding(message_len, mpackets, rpackets);
      }
      else {
	if(part->mess_len != message_len) {
	  Alarm(PRINT, "Decode Recon: "
		"Part->mess_len = %d, message_len = %d, i = %d\n",
		part->mess_len, message_len, i);
	  assert(0);
	}
      }
      
      assert(initialized);
      ERASURE_Set_Encoded_Part(part);
    }
  }
   
  /* Now decode the message */
  mess = UTIL_New_Signed_Message();
  if((ret = ERASURE_Decode(mess)) != 0) {
    Alarm(EXIT, "Could not decode local recon!\n");
  }
  
  /* Sanity check */
  if(message_len != UTIL_Message_Size(mess)) {
    Alarm(PRINT, "Decode Local Recon: Message_len = %d, expected %d\n",
	  message_len, UTIL_Message_Size(mess));
    Alarm(PRINT, "Type = %d, Len = %d\n", mess->type, mess->len);
    assert(0);
  }
  
#if 0
  if(VAL_Validate_Message(mess, message_len) == 0)
    Alarm(EXIT, "Validate failed in Erasure_Decode_Local_Recon\n");
#endif    
  
  assert(mess->type == PO_REQUEST);
  req = (po_request_message *)(mess+1);
  
#if 1
  if(req->seq_num % 250 == 0)
    Alarm(PRINT, "Decoded %d %d\n", mess->machine_id, req->seq_num);
#endif
  
  APPLY_Message_To_Data_Structs(mess);
  DIS_Dispatch_Message(mess);
  dec_ref_cnt(mess);
}

void RECON_Create_Nodes_From_Messages(dll_struct *source_list, 
					dll_struct *dest_list)
{
  signed_message *mess;
  int32u dest_bits, part_len, mess_len;
  erasure_node *n;
  int32u mpackets, rpackets;
  po_request_message *req;

  while(!UTIL_DLL_Is_Empty(source_list)) {
    UTIL_DLL_Set_Begin(source_list);
      
    mess      = UTIL_DLL_Front_Message(source_list);
    dest_bits = UTIL_DLL_Front_Extra(source_list, DEST);

    /* We encode the message into 3f+1 parts, f+1 of which will be 
     * needed to decode. */
    mpackets = NUM_FAULTS+1;
    rpackets = 2*NUM_FAULTS;
    
    ERASURE_Clear();

#if 0
    /* Sanity check */
    if(VAL_Validate_Message(mess, UTIL_Message_Size(mess)) == 0)
      Alarm(EXIT, "Validate failed in Erasure_Create_Nodes\n");
#endif

    ERASURE_Initialize_Encoding(mess, mpackets, rpackets);
      
    /* Length = # encoded bytes + index + size of meta information */
    part_len = ERASURE_Get_Total_Part_Length() + sizeof(erasure_part);
    mess_len = UTIL_Message_Size(mess);
      
    /* Set up a new erasure node to store the encoded parts */
    n = UTIL_New_Erasure_Node(dest_bits, mess->type, part_len, mess_len);
    
    req = (po_request_message *)(mess + 1);
      
    n->originator = mess->machine_id;
    n->seq_num    = req->seq_num;
    
    /* Encode the message and store it into the buffer */
    ERASURE_Encode(n->buf);
    
    /* Store the node in the Erasure List */
    UTIL_DLL_Add_Data(dest_list, n);
    dec_ref_cnt(n);
    assert(get_ref_cnt(n) == 1);
    
    /* Remove the full messsage from the non-broadcast list */
    UTIL_DLL_Pop_Front(source_list);
  }
}

void RECON_Allocate_Recon_Parts_From_Nodes(dll_struct *node_list, 
					   dll_struct *dest_lists)
{
  erasure_node *n;
  erasure_part_obj *ep;
  int32u i, index, target, id;

  /* Iterate over the node list.  For each erasure node (message), add
   * my part to server list server_id if bit is set in dest_bits. */
  while(!UTIL_DLL_Is_Empty(node_list)) {
    UTIL_DLL_Set_Begin(node_list);
    
    n = (erasure_node *)UTIL_DLL_Front_Message(node_list);

    /* Sanity check: this should have some destination */
    assert(n->dest_bits != 0);

    target = NUM_SERVERS;
    
    for(i = 1; i <= target; i++) {

      if(UTIL_Bitmap_Is_Set(&n->dest_bits, i)) {

	/* Build a new object and initialize it with encoding information */
	ep = UTIL_New_Erasure_Part_Obj();
	ep->part.mess_len = n->mess_len;
	ep->mess_type     = n->mess_type;
	ep->part_len      = n->part_len;
	ep->originator    = n->originator;
	ep->seq_num       = n->seq_num;

	/* Copy my part into the object */
	id = VAR.My_Server_ID;

	index = (id - 1) *	
	  ((ep->part_len - sizeof(erasure_part))/sizeof(int32u));
	memcpy(ep->buf, &n->buf[index], n->part_len - sizeof(erasure_part));
        
	/* Add the part to the list and maintain the destination info */
	UTIL_DLL_Add_Data(&dest_lists[i], ep);
	UTIL_DLL_Set_Last_Extra(&dest_lists[i], DEST, n->dest_bits);
	dec_ref_cnt(ep);
	assert(get_ref_cnt(ep) == 1);
      }
    }
    UTIL_DLL_Pop_Front(node_list);
  }
}

void RECON_Build_Recon_Packets(dll_struct *dest_lists)
{
  int32u i, target, more_to_encode, bits;
  signed_message *m;

  target = NUM_SERVERS;

  for(i = 1; i <= target; i++) {
  
    if(UTIL_DLL_Is_Empty(&dest_lists[i]))
      continue;

    while(1) {
      bits = 0;
      
      /* Build the actual packet */
      m = RECON_Construct_Recon_Erasure_Message(&dest_lists[i], 
						  &more_to_encode);
      UTIL_Bitmap_Set(&bits, i);
      if(UTIL_Bitmap_Num_Bits_Set(&bits) != 1) {
	Alarm(PRINT, "Tried to set bit %d but num_bits_set = %d\n",
	      i, UTIL_Bitmap_Num_Bits_Set(&bits));
	assert(0);
      }

      /* The message needs to be RSA signed.  It is sent to those that
       * need it. */
      SIG_Add_To_Pending_Messages(m, bits, UTIL_Get_Timeliness(RECON));
      dec_ref_cnt(m);
      
      if(more_to_encode == 0) {
	assert(UTIL_DLL_Is_Empty(&dest_lists[i]));
	break;
      }
    }
  }
}
