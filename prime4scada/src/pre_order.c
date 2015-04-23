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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "arch.h"
#include "spu_alarm.h"
#include "spu_memory.h"
#include "data_structs.h"
#include "utility.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "packets.h"
#include "apply.h"
#include "order.h"
#include "signature.h"
#include "recon.h"
#include "dispatcher.h"
#include "suspect_leader.h"

/* Globally Accessible Variables */
extern server_variables    VAR;
extern server_data_struct  DATA;
extern benchmark_struct    BENCH;

/* Local Functions */
void   PRE_ORDER_Upon_Receiving_Update      (signed_message *mess);
void   PRE_ORDER_Upon_Receiving_PO_Request  (signed_message *mess);
void   PRE_ORDER_Upon_Receiving_PO_Ack      (signed_message *mess);
void   PRE_ORDER_Upon_Receiving_PO_ARU      (signed_message *mess);
void   PRE_ORDER_Upon_Receiving_Proof_Matrix(signed_message *mess);
int32u PRE_ORDER_Proof_ARU (int32u server, po_aru_signed_message *proof);
void   PRE_ORDER_Periodically(int dummy, void *dummyp);

void PRE_ORDER_Dispatcher(signed_message *mess)
{
  /* All messages are of type signed_message. We assume that:
   *
   * THERE ARE NO CONFLICTS
   *
   * THE MESSAGE HAS BEEN APPLIED TO THE DATA STRUCTURE
   *
   * THE MESSAGE HAS PASSED VALIDATION
   */

  switch (mess->type) {

  case UPDATE:
    PRE_ORDER_Upon_Receiving_Update(mess);
    break;

  case PO_REQUEST:
    PRE_ORDER_Upon_Receiving_PO_Request(mess);
    break;

  case PO_ACK:
    PRE_ORDER_Upon_Receiving_PO_Ack(mess);
    break;

  case PO_ARU:
    PRE_ORDER_Upon_Receiving_PO_ARU(mess);
    break;

  case PROOF_MATRIX:
    PRE_ORDER_Upon_Receiving_Proof_Matrix(mess);
    break;

  case RECON:
    RECON_Upon_Receiving_Recon(mess);
    break;

  default:
    INVALID_MESSAGE("Pre Order");
    Alarm(EXIT, "Unexpected type in PRE_ORDER Dispatcher: %d\n", mess->type);
  }
}

void PRE_ORDER_Upon_Receiving_Update(signed_message *update)
{
  if(DATA.buffering_during_recovery == 1)
    return;

  /* Discard duplicated updates */
  update_message *update_specific;
  update_specific = (update_message *)(update + 1);
  if(update_specific->time_stamp <= DATA.PO.client_ts[update->machine_id])
    return;

  /* Add the update to the outgoing po_request list  */
  UTIL_DLL_Add_Data(&DATA.PO.po_request_dll, update);

  /* If we're not sending PO-Requests periodically, try to send one
   * right away. */
  if(!SEND_PO_REQUESTS_PERIODICALLY)
    PRE_ORDER_Attempt_To_Send_PO_Request();
}

void PRE_ORDER_Attempt_To_Send_PO_Request()
{
  signed_message *po_request;
  double time;
  int32u dest_bits;
  int32u counter = 0;

  /* If we send PO-Requests periodically, make sure it's been long
   * enough since we last sent one. */
  if(SEND_PO_REQUESTS_PERIODICALLY) {
    UTIL_Stopwatch_Stop(&DATA.PO.po_request_sw);
    time = UTIL_Stopwatch_Elapsed(&DATA.PO.po_request_sw);
    if(time < ((PO_PERIODICALLY_USEC / 1000000.0) * 
	       PO_REQUEST_PERIOD))
      return;
  }

  while(!UTIL_DLL_Is_Empty(&DATA.PO.po_request_dll)) {

    /* Build a new PO_Request */
    po_request = PRE_ORDER_Construct_PO_Request();

    /* Broadcast by default.  Only changed if there is a RECON_ATTACK. */
    dest_bits = BROADCAST;
    
    /* Recon attack: */
    if(UTIL_I_Am_Faulty()) {
      /* Set the destination bits to everyone except server 4 */
      int32u i;
      for(i = 1; i <= NUM_SERVERS; i++) {
	if(i != VAR.My_Server_ID && i < 4)
	  UTIL_Bitmap_Set(&dest_bits, i);
      }
    }

    /* Add it to the list of messages to be signed*/
    SIG_Add_To_Pending_Messages(po_request, dest_bits, 
				UTIL_Get_Timeliness(PO_REQUEST));
    dec_ref_cnt(po_request);
    counter++;

    /* Sanity check.  This indicates an infinite loop. Should never happen. */
    if(counter == 500) {
      Alarm(DEBUG, "Length of po_request_dll is %d\n", 
	    DATA.PO.po_request_dll.length);
      Alarm(DEBUG, "DATA.PO.po_seq_num = %d\n", DATA.PO.po_seq_num);
      assert(0);
    }
  }

  if(counter > 0)
    Alarm(DEBUG, "Batched %d local PO-Requests\n", counter);

  /* If we sent one, don't do it again for a little while */
  if(SEND_PO_REQUESTS_PERIODICALLY && (counter > 0))
    UTIL_Stopwatch_Start(&DATA.PO.po_request_sw);
}

void PRE_ORDER_Upon_Receiving_PO_Request(signed_message *po_request)
{
  if(!SEND_PO_ACKS_PERIODICALLY)
    PRE_ORDER_Send_PO_Ack();
}

void PRE_ORDER_Periodically(int dummy, void *dummyp)
{
  sp_time t;

  //TODO: I want to stop measuring turnaround time during preinstall
  // but is this the right way to do it?
  if (!DATA.preinstall) {
    SIG_Attempt_To_Generate_PO_Messages();
  }

  /* Re-schedule the event for next time */
  t.sec  = PO_PERIODICALLY_SEC;
  t.usec = PO_PERIODICALLY_USEC;
  E_queue(PRE_ORDER_Periodically, 0, NULL, t);
}

void PRE_ORDER_Send_PO_Ack()
{
  signed_message *ack;
  int32u more_to_ack;
  double time;

  if(DATA.buffering_during_recovery == 1)
    return;

  /* Make sure we don't send an ack if it hasn't been long enough */
  if(SEND_PO_ACKS_PERIODICALLY) {
    UTIL_Stopwatch_Stop(&DATA.PO.po_ack_sw);
    time = UTIL_Stopwatch_Elapsed(&DATA.PO.po_ack_sw);
    if(time < (PO_PERIODICALLY_USEC / 1000000.0) * PO_ACK_PERIOD)
      return;
  }

  /*  First make sure our local Pre-Order ARU is up to date. */
  PRE_ORDER_Update_ARU();
  
  while(1) {

    /* Now construct the Local PO_Ack */
    ack = PRE_ORDER_Construct_PO_Ack(&more_to_ack);
  
    /* Ack may be NULL if there is no ack to send right now */
    if (ack == NULL)
      break;

    SIG_Add_To_Pending_Messages(ack, BROADCAST, UTIL_Get_Timeliness(PO_ACK));
    dec_ref_cnt(ack);

    if(SEND_PO_ACKS_PERIODICALLY)
      UTIL_Stopwatch_Start(&DATA.PO.po_ack_sw);
    
    /* If they tell us there's nothing more to ack, then we're done. */
    if(more_to_ack == 0)
      break;
  }
}

int32u PRE_ORDER_Update_ARU() 
{
  int32u s;
  bool updated = FALSE;
  po_slot *slot;

  /* Attempt to update the pre order aru for each server */
  for (s = 1; s <= NUM_SERVERS; s++) {

    while((slot = UTIL_Get_PO_Slot_If_Exists(s, DATA.PO.aru[s]+1))
	  != NULL){
      if (slot->po_request == NULL) {
	/* NULL request -- don't update aru */
	Alarm(DEBUG,"%d NULL po_request found in slot %d srv %d\n",
	      VAR.My_Server_ID, DATA.PO.aru[s]+1, s );
	break;
      }
      DATA.PO.aru[s]++; 
      updated = TRUE;
    }
  }
  
  return updated;
}

void PRE_ORDER_Upon_Receiving_PO_Ack(signed_message *po_ack)
{
  if(!SEND_PO_ARU_PERIODICALLY)
    PRE_ORDER_Send_PO_ARU();
}

void PRE_ORDER_Send_PO_ARU()
{
  signed_message *ack;
  double time;

  if(DATA.buffering_during_recovery == 1)
    return;

  /* Make sure it's been long enough since we last sent a PO-ARU */
  if(SEND_PO_ARU_PERIODICALLY) {
    UTIL_Stopwatch_Stop(&DATA.PO.po_aru_sw);
    time = UTIL_Stopwatch_Elapsed(&DATA.PO.po_aru_sw);
    if(time < (PO_PERIODICALLY_USEC / 1000000.0) * (PO_ARU_PERIOD))
      return;
  }

  /* Only send the message if there's something new to report */
  if(!PRE_ORDER_Update_Cum_ARU()) 
    return;

  ack = PRE_ORDER_Construct_PO_ARU();
  assert(ack);

  //SIG_Add_To_Pending_Messages(ack, BROADCAST, UTIL_Get_Timeliness(PO_ARU));
  UTIL_RSA_Sign_Message(ack); //need messages to be compact, so no merkle tree stuff...
  UTIL_Broadcast(ack);
  APPLY_PO_ARU(ack); //broadcast doesn't send it to myself, so apply to datastructs
  dec_ref_cnt(ack);

  /* Mark that we've just sent one so we don't do it again for awhile */
  UTIL_Stopwatch_Start(&DATA.PO.po_aru_sw);
}

int32u PRE_ORDER_Update_Cum_ARU()
{
  int32u s;
  po_slot *slot;
  bool updated = FALSE;

  /* Attempt to update the pre order cumulative aru for each server */
  
  for (s = 1; s <= NUM_SERVERS; s++) {
    while((slot = UTIL_Get_PO_Slot_If_Exists(s, DATA.PO.cum_aru[s]+1))!= NULL) {

      /* Make sure we have the PO Request */
      if(slot->po_request == NULL)
	break;

      if(slot->ack_count < (2 * NUM_FAULTS + 1)) {
	/* not enough acks -- don't update aru */
	break;
      }

      /* Enough acks found for server s*/
      DATA.PO.cum_aru[s]++; 
      updated = TRUE;
    }
  }
  
  return updated;
}

void PRE_ORDER_Upon_Receiving_PO_ARU(signed_message *mess)
{
  Alarm(DEBUG, "Server: %d, PRE_ORDER Received PO-ARU %d from %d\n",
        VAR.My_Server_ID, DATA.PO.aru[mess->machine_id], mess->machine_id );

  /* If we're not sending the Proof Matrix periodically, then try to
   * send one whenever we receive a new PO-ARU message.  Otherwise,
   * we'll send it periodically in response to a timeout. */

  if(!SEND_PROOF_MATRIX_PERIODICALLY && !UTIL_I_Am_Leader())
    PRE_ORDER_Send_Proof_Matrix();

  /* The leader will send out Pre-Prepares periodically. */
}

void PRE_ORDER_Send_Proof_Matrix()
{
  signed_message *mset[NUM_SERVER_SLOTS];
  int32u num_parts, i, dest_bits;
  double time;

  if(DATA.buffering_during_recovery == 1)
    return;

  /* Leader does not send proof matrix to itself */
  assert(!UTIL_I_Am_Leader());

  /* Make sure it's been long enough since we last sent a Proof Matrix */
  if(SEND_PROOF_MATRIX_PERIODICALLY) {
    UTIL_Stopwatch_Stop(&DATA.PO.proof_matrix_sw);
    time = UTIL_Stopwatch_Elapsed(&DATA.PO.proof_matrix_sw);
    if(time < (PO_PERIODICALLY_USEC / 1000000.0) * 
       (PROOF_MATRIX_PERIOD))
      return;
  }

  //JCS: Thesis specifies that each correct server should always periodically 
  // send matrix

  /*
  if (PRE_ORDER_Latest_Proof_Sent()) {
	//already sent the latest proof, don't send it again
        return;
  }
  */

  PRE_ORDER_Construct_Proof_Matrix(mset, &num_parts);

  /* We are definitely sending the proof */
  PRE_ORDER_Update_Latest_Proof_Sent();

  for(i = 1; i <= num_parts; i++) {
    assert(mset[i]);

    /* Add the constructed part to the queue of messages to be signed.
     * The message will be sent only to the leader. */
    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, UTIL_Leader());
    SIG_Add_To_Pending_Messages(mset[i], dest_bits, 
				UTIL_Get_Timeliness(PROOF_MATRIX));
    dec_ref_cnt(mset[i]);
  }

  /* Mark that we've just sent a proof matrix so we don't do it again
   * for while. */
  UTIL_Stopwatch_Start(&DATA.PO.proof_matrix_sw);

  SUSPECT_Start_Measure_TAT();
}

bool PRE_ORDER_Latest_Proof_Sent() 
{
  int32u s;
  int32u paru;

  /* Has the most up to date proof already been sent?  Check to see if
   * the current proof contains new information that has not been sent
   * yet.  Returns FALSE if any slot is out of date. */
  for (s = 1; s <= NUM_SERVERS; s++) {
    paru = PRE_ORDER_Proof_ARU(s, DATA.PO.cum_acks+1);
    if(paru > DATA.PO.max_num_sent_in_proof[s]) {
      return FALSE;
    }
  }

  return TRUE;
}

int32u PRE_ORDER_Proof_ARU(int32u server, po_aru_signed_message *proof) 
{
  int32u s;
  int32u cack[NUM_SERVER_SLOTS];

  /* A proof aru */
  for (s = 1; s <= NUM_SERVERS; s++)
    cack[s] = proof[s-1].cum_ack.ack_for_server[server-1];

  /* sort the values */
  qsort( (void*)(cack+1), NUM_SERVERS, sizeof(int32u), intcmp );
  return cack[VAR.Faults + 1];
}

void PRE_ORDER_Update_Latest_Proof_Sent() 
{
  int32u s;
  int32u paru;
  
  /* We are sending a proof based on the current local po_arus */

  for (s = 1; s <= NUM_SERVERS; s++) {
    paru = PRE_ORDER_Proof_ARU(s, DATA.PO.cum_acks+1);
    if (paru > DATA.PO.max_num_sent_in_proof[s])
      DATA.PO.max_num_sent_in_proof[s] = paru;
  }
}

void PRE_ORDER_Upon_Receiving_Proof_Matrix(signed_message *mess)
{
   /* 
    if (VAR.My_Server_ID == 2 && UTIL_I_Am_Leader()) {
	Alarm(PRINT, "Replaying Proof_Matrix\n");
	int i;
	for (i = 0; i < 20; i++) {
	    UTIL_Broadcast(mess);
	}
    }
   */

  /* If the delay attack is running and I am the leader, then I must
   * respond. */

#if DELAY_ATTACK
  if (VAR.My_Server_ID == 2 /*&& UTIL_I_Am_Leader()*/) {
    UTIL_DLL_Add_Data(&DATA.PO.proof_matrix_dll, mess);
    Alarm(DEBUG, "ADD\n"  );
  }
#endif

}

void PRE_ORDER_Garbage_Collect_PO_Slot(int32u server_id, int32u seq_num)
{
  po_slot *slot;
  recon_slot *r_slot;

  slot = UTIL_Get_PO_Slot_If_Exists(server_id, seq_num);

  /* Slot should not be NULL because in theory we just executed this
   * preordered request. */
  assert(slot != NULL);

  /* Clean out the PO-Request from the slot. */
  assert(slot->po_request != NULL);
  dec_ref_cnt(slot->po_request);

  /* Now remove the slot itself */
  dec_ref_cnt(slot);
  stdhash_erase_key(&DATA.PO.History[server_id], &seq_num);

  if(seq_num != (DATA.PO.white_line[server_id] + 1)) {
    Alarm(DEBUG, "Garbage collecting %d %d, white_line+1 = %d\n",
	  server_id, seq_num, DATA.PO.white_line[server_id]+1);
    //assert(0);
  }
  DATA.PO.white_line[server_id] = seq_num;

  /* If we had any reconciliation messages for this preorder id, discard
   * the associated slot. */
  if((r_slot = UTIL_Get_Recon_Slot_If_Exists(server_id, seq_num))) {
    assert(get_ref_cnt(r_slot) == 1);
    dec_ref_cnt(r_slot);
    stdhash_erase_key(&DATA.PO.Recon_History[server_id], &seq_num);
  }
}

void PRE_ORDER_Initialize_Data_Structure()
{
  int32u s, s2;
  
  for (s = 1; s <= NUM_SERVERS; s++) {
    /* for each server, */
    DATA.PO.max_acked[s]             = 0;
    DATA.PO.aru[s]                   = 0;
    DATA.PO.cum_aru[s]               = 0;
    DATA.PO.max_num_sent_in_proof[s] = 0;
    DATA.PO.white_line[s]            = 0;

    for(s2 = 1; s2 <= NUM_SERVERS; s2++)
      DATA.PO.cum_max_acked[s][s2] = 0;
  }

  memset(DATA.PO.cum_acks, (sizeof(po_aru_signed_message ) *
			    NUM_SERVER_SLOTS), 0);
  
  /* Construct the local PO History */
  for (s = 1; s <= NUM_SERVERS; s++) {
    stdhash_construct(&DATA.PO.History[s], sizeof(int32u),
		      sizeof(po_slot *), NULL, NULL, 0);
    stdhash_construct(&DATA.PO.Pending_Execution[s], sizeof(int32u),
		      sizeof(ord_slot *), NULL, NULL, 0);
    stdhash_construct(&DATA.PO.Recon_History[s], sizeof(int32u),
		      sizeof(recon_slot *), NULL, NULL, 0);
  }

  UTIL_Stopwatch_Start(&DATA.PO.po_request_sw);
  UTIL_Stopwatch_Start(&DATA.PO.po_ack_sw);
  UTIL_Stopwatch_Start(&DATA.PO.po_aru_sw);
  UTIL_Stopwatch_Start(&DATA.PO.proof_matrix_sw);
  UTIL_Stopwatch_Start(&DATA.PO.token_stopwatch);

  DATA.PO.tokens = 0;

  DATA.PO.po_seq_num     = 1;
  DATA.PO.po_aru_num     = 1;

  UTIL_DLL_Initialize(&DATA.PO.po_request_dll);
  UTIL_DLL_Initialize(&DATA.PO.proof_matrix_dll);

  /* Start trying to periodically send Pre-Order messages */
  PRE_ORDER_Periodically(0, NULL);
}
