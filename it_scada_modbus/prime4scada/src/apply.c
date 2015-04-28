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

/* Apply messages to the data structures. These functions take a message that
 * has been validated and applies it to the data structures. */
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "data_structs.h"
#include "apply.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "error_wrapper.h"
#include "utility.h"
#include "order.h"
#include "recon.h"
#include "pre_order.h"
#include "objects.h"

/* Gobally Accessible Variables */
extern server_variables   VAR;
extern server_data_struct DATA;

void APPLY_Update      (signed_message *update); 
void APPLY_PO_Request  (signed_message *mess);
void APPLY_PO_Ack      (signed_message *mess);
void APPLY_PO_ARU      (signed_message *mess);
void APPLY_Proof_Matrix(signed_message *mess);
void APPLY_Pre_Prepare (signed_message *mess);
void APPLY_Prepare     (signed_message *mess);
void APPLY_Commit      (signed_message *mess);
void APPLY_Recon       (signed_message *mess);
void APPLY_RTT_Ping    (signed_message *mess);
void APPLY_RTT_Pong    (signed_message *mess);
void APPLY_RTT_Measure (signed_message *mess);
void APPLY_TAT_Measure (signed_message *mess);
void APPLY_TAT_UB (signed_message *mess);
void APPLY_New_Leader (signed_message *mess);
void APPLY_New_Leader_Proof (signed_message *mess);
void APPLY_RB_Init (signed_message *mess);
void APPLY_RB_Echo (signed_message *mess);
void APPLY_RB_Ready (signed_message *mess);
void APPLY_Report (signed_message *mess);
void APPLY_PC_Set (signed_message *mess);
void APPLY_VC_List (signed_message *mess);
void APPLY_VC_Partial_Sig (signed_message *mess);
void APPLY_VC_Proof (signed_message *mess);
void APPLY_Replay (signed_message *mess);
void APPLY_Replay_Prepare (signed_message *mess);
void APPLY_Replay_Commit (signed_message *mess);

int32u APPLY_Prepare_Certificate_Ready(ord_slot *slot);
void   APPLY_Move_Prepare_Certificate (ord_slot *slot);
int32u APPLY_Prepare_Matches_Pre_Prepare(signed_message *prepare,
					 complete_pre_prepare_message *pp);

int32u APPLY_Commit_Certificate_Ready  (ord_slot *slot);
void   APPLY_Move_Commit_Certificate   (ord_slot *slot);
int32u APPLY_Commit_Matches_Pre_Prepare(signed_message *commit,
					complete_pre_prepare_message *pp);

/* Apply a signed message to the data structures. */
void APPLY_Message_To_Data_Structs(signed_message *mess) 
{

  /* Does not process any message during recovery*/
  if(DATA.recovery_in_progress == 1 && mess->type != NEW_LEADER && mess->type != NEW_LEADER_PROOF)
    return;

  switch (mess->type) {   

  case UPDATE:
    APPLY_Update(mess);
    break;

  case PO_REQUEST:
    APPLY_PO_Request(mess);
    break;
    
  case PO_ACK:
    APPLY_PO_Ack(mess);
    break;

  case PO_ARU:
    
    /* If the delay attack is used, the leader ignores PO-ARU messages 
     * and only handles proof matrix messages when it needs to. */
#if DELAY_ATTACK
    if(VAR.My_Server_ID != 2 || !UTIL_I_Am_Leader())
      APPLY_PO_ARU(mess);
#else
    APPLY_PO_ARU(mess);
#endif
    break;

  case PROOF_MATRIX:

    /* If the delay attack is used, the leader adds the proof matrix
     * message to a queue and only processes it when it needs to, when
     * it comes time to send the Pre-Prepare. */
#if DELAY_ATTACK
    if(VAR.My_Server_ID != 2 || !UTIL_I_Am_Leader())
      APPLY_Proof_Matrix(mess);
#else
    APPLY_Proof_Matrix(mess);
#endif
    break;
    
  case PRE_PREPARE:
    APPLY_Pre_Prepare(mess);
    break;

  case PREPARE:
    APPLY_Prepare(mess);
    break;

  case COMMIT:
    APPLY_Commit(mess);
    break;

  case RTT_PING:
    APPLY_RTT_Ping(mess);
    break;

  case RTT_PONG:
    APPLY_RTT_Pong(mess);
    break;

  case RTT_MEASURE:
    APPLY_RTT_Measure(mess);
    break;

  case TAT_MEASURE:
    APPLY_TAT_Measure(mess);
    break;

  case TAT_UB:
    APPLY_TAT_UB(mess);
    break;

  case NEW_LEADER:
    APPLY_New_Leader(mess);
    break;

  case NEW_LEADER_PROOF:
    APPLY_New_Leader_Proof(mess);
    break;

  case RB_INIT:
    APPLY_RB_Init(mess);
    break;

  case RB_ECHO:
    APPLY_RB_Echo(mess);
    break;

  case RB_READY:
    APPLY_RB_Ready(mess);
    break;

  case REPORT:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_Report(mess);
    break;

  case PC_SET:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_PC_Set(mess);
    break;

  case VC_LIST:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_VC_List(mess);
    break;

  case VC_PARTIAL_SIG:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_VC_Partial_Sig(mess);
    break;

  case VC_PROOF:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_VC_Proof(mess);
    break;

  case REPLAY:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_Replay(mess);
    break;

  case REPLAY_PREPARE:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_Replay_Prepare(mess);
    break;

  case REPLAY_COMMIT:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_Replay_Commit(mess);
    break;

  case RECON:
    if(DATA.buffering_during_recovery == 1)
      return;
    APPLY_Recon(mess);
    break;

  case ORD_CERT:
    /* Nothing to do here */
    break;

  case ORD_CERT_REPLY:
    /* Nothing to do here */
    break;

  case PO_CERT:
    /* Nothing to do here */
    break;

  case PO_CERT_REPLY:
    /* Nothing to do here */
    break;

  case DB_STATE_DIGEST_REQUEST:
    /* Nothing to do here */
    break;
          
  case DB_STATE_DIGEST_REPLY:
    /* Nothing to do here */
    break;
          
  case DB_STATE_VALIDATION_REQUEST:
    /* Nothing to do here */
    break;

  case DB_STATE_VALIDATION_REPLY:
    /* Nothing to do here */
    break;

  case DB_STATE_TRANSFER_REQUEST:
    /* Nothing to do here */
    break;

  case DB_STATE_TRANSFER_REPLY:
    /* Nothing to do here */
    break;

  case CATCH_UP:
    /* Nothing to do here */
    break;

  case CATCH_UP_REPLY:
    /* Nothing to do here */
    break;

  default:
    Alarm(EXIT, "Unexpected message type in APPLY message: %d\n", mess->type);
    return;
  }
}

void APPLY_Update(signed_message *update)
{
  /* Nothing to do */
}

void APPLY_PO_Request(signed_message *po_request)
{
  po_slot *slot;
  po_request_message *po_request_specific;
  int32u id, seq_num;
  stdit it;

  /* Get the po slot for this message and store the po_request in this slot */
  po_request_specific = (po_request_message*)(po_request+1);

  Alarm(DEBUG, "APPLY PO_REQUEST %d %d\n", 
	po_request->machine_id, po_request_specific->seq_num);

  /* If we've already garbage collected this slot, don't do anything */
  if(po_request_specific->seq_num <= 
     DATA.PO.white_line[po_request->machine_id]) {
    Alarm(DEBUG, "Discarding PO-Request %d %d, already gc\n",
	  po_request->machine_id, po_request_specific->seq_num);
    return;
  }    

  assert((po_request->machine_id >= 1) && 
	 (po_request->machine_id <= NUM_SERVERS));

  slot = UTIL_Get_PO_Slot(po_request->machine_id, po_request_specific->seq_num);
  
  /* If we already have this po request, don't do anything */
  if(slot->po_request) {
    Alarm(DEBUG, "Discarding PO-Request %d %d, already have it.\n",
	  po_request->machine_id, po_request_specific->seq_num);
    return;
  }

  /* Store the po_request if we need it. */
  inc_ref_cnt(po_request); 
  slot->po_request  = po_request;

  PRE_ORDER_Update_ARU();

  slot->num_events = po_request_specific->num_events;
  slot->executed = 0;
  /* See if we were missing this PO-Request when it became eligible for
   * local execution.  If so, mark that we have it.  Then, if this means
   * we can execute the next global sequence number, try. */
  id      = po_request->machine_id;
  seq_num = po_request_specific->seq_num;
  stdhash_find(&DATA.PO.Pending_Execution[id], &it, &seq_num);

  if(!stdhash_is_end(&DATA.PO.Pending_Execution[id], &it)) {
    ord_slot *o_slot;

    o_slot = *((ord_slot **)stdhash_it_val(&it));
    dec_ref_cnt(o_slot);
    stdhash_erase_key(&DATA.PO.Pending_Execution[id], &seq_num);
    o_slot->num_remaining_for_execution--;

    assert(o_slot->num_remaining_for_execution >= 0);

    Alarm(DEBUG, "Received missing po-request %d %d\n", id, seq_num);

    if(o_slot->num_remaining_for_execution == 0) {
      sp_time t;
      t.sec = 0; t.usec = 0;
      E_queue(ORDER_Attempt_To_Execute_Pending_Commits, 0, 0, t);
    }    

    Alarm(DEBUG, "Filled hole\n");
  }
}

void APPLY_PO_Ack(signed_message *po_ack)
{
  po_slot *slot;
  po_ack_message *po_ack_specific;
  po_ack_part *part;
  int32u p;

  /* Iterate over each ack in the aggregate PO-Ack, and apply it to
   * the correct po slot */
  Alarm(DEBUG, "PO_Ack from %d\n", po_ack->machine_id);

  po_ack_specific = (po_ack_message *)(po_ack+1);
  part            = (po_ack_part *)(po_ack_specific+1);

  for (p = 0; p < po_ack_specific->num_ack_parts; p++) {

    /* Mark if I can use this to increase my knowledge of which PO-Requests
     * from originator it has contiguously received and acknowledged. */
    if(part[p].seq_num > 
       DATA.PO.cum_max_acked[po_ack->machine_id][part[p].originator]) {
      DATA.PO.cum_max_acked[po_ack->machine_id][part[p].originator] = 
	part[p].seq_num;
    }

    /* If we've already garbage collected this slot, don't do anything */
    if(part[p].seq_num <= DATA.PO.white_line[part[p].originator])
      continue;
    
    slot = UTIL_Get_PO_Slot(part[p].originator, part[p].seq_num);
    
    /* TODO --- check to see if digests match -- this should be done
     * in conflict */

    if(!slot->ack_received[po_ack->machine_id]) {
      slot->ack_received[po_ack->machine_id] = TRUE;
      slot->ack_count++;
      /* We store received PO-ACKs in the po_slot for proactive recovery */
      #if RECOVERY
      if(slot->po_ack[po_ack->machine_id] == NULL) {
         inc_ref_cnt(po_ack);
         slot->po_ack[po_ack->machine_id] = po_ack;
      }
      #endif
    }
  }
}

void APPLY_PO_ARU(signed_message *po_aru)
{
  int32u prev_num;
  int32u num;
  po_aru_signed_message *prev, *cur;
  int32u i, val;
  cur = (po_aru_signed_message *)po_aru;
  /* If the PO_ARU is contained in a Proof matrix, then it may be a null
   * vector.  Don't apply it in this case. */
  if(po_aru->type != PO_ARU)
    return;

  /* We will store the latest PO-ARU received from each server -- this
   * constitutes the proof */

  prev = &(DATA.PO.cum_acks[po_aru->machine_id]);

  num      = ((po_aru_message*)(po_aru+1))->num;
  prev_num = prev->cum_ack.num;

  int32u check = 1;

  if (num < prev_num)
    check = 0;

  for (i = 0; i < NUM_SERVERS; ++i) {
    if (cur->cum_ack.ack_for_server[i] < prev->cum_ack.ack_for_server[i]) {
      check = 0;
      break;
    }
  }

  /* TODO: We should really check to make sure they are consistent here,
   * rather than just blindly adopting the one with the highest number. */
  if(check) {
    memcpy( (void*)( &DATA.PO.cum_acks[po_aru->machine_id]), 
	    (void*)po_aru, sizeof(po_aru_signed_message));
  }

  /* See if I can use this to increase my knowledge of what the acker
   * has contiguously received with respect to po-requests */

  for(i = 1; i <= NUM_SERVERS; i++) {
    val = cur->cum_ack.ack_for_server[i-1];

    if(DATA.PO.cum_max_acked[po_aru->machine_id][i] < val)
      DATA.PO.cum_max_acked[po_aru->machine_id][i] = val;
  }
}

void APPLY_Proof_Matrix(signed_message *pm)
{
  int32u s;
  po_aru_signed_message *cum_ack;
  proof_matrix_message *pm_specific;

  /* No need to apply my own Local Proof Matrix */
  if(VAR.My_Server_ID == pm->machine_id)
    return;

  Alarm(DEBUG, "Received a proof matrix from server %d\n", pm->machine_id);

  /* The proof is a collection of po_arus -- apply each one */
  pm_specific = (proof_matrix_message *)(pm + 1);
  
  cum_ack = (po_aru_signed_message *)(pm_specific + 1);

  for(s = 0; s < pm_specific->num_acks_in_this_message; s++)
    APPLY_PO_ARU((signed_message *)&cum_ack[s]);
}

void APPLY_Pre_Prepare (signed_message *mess)
{
    pre_prepare_message *pre_prepare_specific;
    ord_slot *slot;
    int32u index, part_num;

    pre_prepare_specific = (pre_prepare_message *)(mess + 1);
    if (pre_prepare_specific->view != DATA.View) {
	//possible if leader sends pre-prepare, but then view changes to get here
	return;
    }

    Alarm(DEBUG, "APPLY Pre_Prepare\n");

    /* If we're done forwarding for this slot, and we've already reconciled
     * on this slot and the next, and we've already executed this slot and
     * the next one, then there's no reason to do anything else with this
     * sequence number. */
    if(pre_prepare_specific->seq_num <= DATA.ORD.forwarding_white_line &&
	    (pre_prepare_specific->seq_num+1) <= DATA.ORD.recon_white_line &&
	    (pre_prepare_specific->seq_num+1) <= DATA.ORD.ARU)
	return;

    /* Something to do: Get the slot */
    slot = UTIL_Get_ORD_Slot(pre_prepare_specific->seq_num);

    /* If we've already collected all of the parts, ignore */
    if(slot->collected_all_parts)
	return;

    slot->seq_num     = pre_prepare_specific->seq_num;
    slot->view        = pre_prepare_specific->view;
    slot->total_parts = pre_prepare_specific->total_parts;
    part_num          = pre_prepare_specific->part_num;

    slot->complete_pre_prepare.seq_num = slot->seq_num;
    slot->complete_pre_prepare.view    = slot->view;

    /* If we need this part, store it.  Then see if we've now collected
     * all of the parts. */
    if(slot->pre_prepare_parts[part_num] == 0) {

	slot->pre_prepare_parts[part_num] = 1;
	Alarm(DEBUG, "Storing Pre-Prepare part %d for seq %d\n",
		part_num, slot->seq_num);

	if(part_num == 1)
	    index = 0;
	else
	    index = (3*NUM_FAULTS+1) / 2;

	/* Copy the bytes of this Pre-Prepare into the complete PP */
	Alarm(DEBUG, "Copying part %d to starting index %d\n", part_num, index);
	memcpy((byte *)(slot->complete_pre_prepare.cum_acks + index),
		(byte *)(pre_prepare_specific + 1),
		sizeof(po_aru_signed_message) *
		pre_prepare_specific->num_acks_in_this_message);
	
        slot->num_parts_collected++;

	if(slot->num_parts_collected == slot->total_parts) {

	    slot->collected_all_parts = 1;
	    slot->should_handle_complete_pre_prepare = 1;


	    /* If I'm the leader, mark that I've forwarded all parts because
	     * I never go and forward them. */
	    if(UTIL_I_Am_Leader()) {
		slot->num_forwarded_parts = slot->total_parts;
		ORDER_Update_Forwarding_White_Line();
	    }

	    /* A Prepare certificate could be ready if we get some Prepares
	     * before we get the Pre-Prepare. */
	    if(APPLY_Prepare_Certificate_Ready(slot))
		APPLY_Move_Prepare_Certificate(slot);
	}
    }
}

void APPLY_Prepare(signed_message *prepare)
{
  prepare_message *prepare_specific;
  ord_slot  *slot;

  Alarm(DEBUG, "%d APPLY_Prepare\n",VAR.My_Server_ID);

  prepare_specific = (prepare_message *)(prepare+1);

  /* If we've already executed this seq, discard */
  if(prepare_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(prepare_specific->seq_num);
  assert(slot->seq_num == prepare_specific->seq_num);

  if (slot->ordered || slot->bound) 
    return;

  /* If I don't already have a Prepare from this server, store it */
  if(slot->prepare[prepare->machine_id] == NULL) {
    inc_ref_cnt(prepare);
    slot->prepare[prepare->machine_id] = prepare;

    Alarm(DEBUG,"PREPARE %d %d \n", prepare, get_ref_cnt(prepare) );

    if(APPLY_Prepare_Certificate_Ready(slot))
      APPLY_Move_Prepare_Certificate(slot);
  }
}

int32u APPLY_Prepare_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **prepare;
  int32u pcount, sn;

  /* Need a Pre_Prepare for a Prepare Certificate to be ready */
  if(slot->collected_all_parts == 0)
    return 0;

  pp   = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  prepare = (signed_message **)slot->prepare;
  pcount = 0;

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if(prepare[sn] != NULL) {
      if(APPLY_Prepare_Matches_Pre_Prepare(prepare[sn], pp)) {
        pcount++;
      } else {
        Alarm(PRINT,"PREPARE didn't match pre-prepare while "
              "checking for prepare certificate.\n");
        dec_ref_cnt(prepare[sn]);
        prepare[sn] = NULL;
      }
    }
  }

  /* If we have the Pre-Prepare and 2f Prepares, we're good to go */
  if (pcount >= VAR.Faults * 2) {
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }
  
  return 0;
}

int32u APPLY_Prepare_Matches_Pre_Prepare(signed_message *prepare,
					 complete_pre_prepare_message *pp)
{
  int32u seq_num, view;
  prepare_message *prepare_specific;
  byte digest[DIGEST_SIZE+1];

  seq_num = pp->seq_num;
  view    = pp->view;

  prepare_specific = (prepare_message*)(prepare+1);

  if(view != prepare_specific->view) {
    Alarm(DEBUG,"v %d %d %d\n", view, prepare_specific->view,
          prepare_specific->seq_num);
    return 0;
  }

  if(seq_num != prepare_specific->seq_num)
    return 0;

  /* Make a digest of the content of the pre_prepare, then compare it
   * to the digest in the Prepare. */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);

  /* This compare was commented out */
  if(!OPENSSL_RSA_Digests_Equal(digest, prepare_specific->digest)) {
    Alarm(PRINT, "Digests don't match.\n");
    return 0;
  }

  return 1;
}

void APPLY_Move_Prepare_Certificate(ord_slot *slot)
{
  int32u pcount;
  int32u sn;
  signed_message **prepare_src;

  Alarm(DEBUG, "Made Prepare Certificate\n");
  
  pcount      = 0;
  prepare_src = (signed_message **)slot->prepare;

  /*Copy the completed Pre-Prepare into the Prepare Certificate */
  memcpy(&slot->prepare_certificate.pre_prepare, &slot->complete_pre_prepare,
         sizeof(complete_pre_prepare_message));

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if (prepare_src[sn] != NULL) {
      
      if(APPLY_Prepare_Matches_Pre_Prepare(prepare_src[sn],
                                     &slot->prepare_certificate.pre_prepare)) {
        slot->prepare_certificate.prepare[sn] = prepare_src[sn];
        prepare_src[sn] = NULL;
      } else {
        Alarm(EXIT,"PREPARE didn't match pre-prepare while "
              "moving prepare certificate.\n");
      }
    }
  }

  /* Mark that we have a Prepare Certificate.*/
  slot->prepare_certificate_ready = 1;
  slot->bound = 1;
}

void APPLY_Commit(signed_message *commit)
{
  commit_message *commit_specific;
  ord_slot *slot;

  Alarm(DEBUG, "%d APPLY_COMMIT\n",VAR.My_Server_ID);

  commit_specific = (commit_message*)(commit+1);

  /* If we've already globally executed this seq, discard */
  if(commit_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(commit_specific->seq_num);
  
  if(slot->ordered)
    return;

  /* If I have not yet received a commit from this server, store it and
   * see if a commit certificate is ready. */
  if(slot->commit[commit->machine_id] == NULL) {
    inc_ref_cnt(commit);
    slot->commit[commit->machine_id] = commit;
    
    if(APPLY_Commit_Certificate_Ready(slot))
      APPLY_Move_Commit_Certificate(slot);
  }
}

int32u APPLY_Commit_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **commit;
  int32u pcount;
  int32u sn;

  if(slot->collected_all_parts == 0)
    return 0;

  pp = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  commit = (signed_message **)slot->commit;
  pcount = 0;

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if(commit[sn] != NULL) {
      if(APPLY_Commit_Matches_Pre_Prepare(commit[sn], pp)) {
	pcount++;
      } else {
	Alarm(PRINT, "COMMIT didn't match Pre-Prepare\n");
        dec_ref_cnt(commit[sn]);
	commit[sn] = NULL;
      }
    }
  }

  if(pcount >= (VAR.Faults * 2 + 1)) {
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }
  
  return 0;
}

int32u APPLY_Commit_Matches_Pre_Prepare(signed_message *commit,
					complete_pre_prepare_message *pp)
{
  int32u seq_num, view;
  commit_message *commit_specific;
  byte digest[DIGEST_SIZE+1]; 

  seq_num = pp->seq_num;
  view    = pp->view;
  
  commit_specific = (commit_message*)(commit+1);

  if(view != commit_specific->view) {
    Alarm(DEBUG,"v %d %d %d\n", view, commit_specific->view,
          commit_specific->seq_num);
    return 0;
  }

  if(seq_num != commit_specific->seq_num)
    return 0;
  
  /* Make a digest of the content of the pre_prepare. */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);

  if(!OPENSSL_RSA_Digests_Equal(digest, commit_specific->digest))
    return 0;
  
  return 1;
}

void APPLY_Move_Commit_Certificate(ord_slot *slot)
{
  int32u pcount;
  int32u sn;
  signed_message **commit_src;
  complete_pre_prepare_message *pp;

  Alarm(DEBUG, "Made commit certificate.\n");

  pcount     = 0;
  commit_src = (signed_message **)slot->commit;
  
  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if((commit_src)[sn] != NULL) {
      Alarm(DEBUG,"APPLY_Move_Commit_Certificate %d\n", commit_src[sn]);

      if(slot->prepare_certificate_ready)
	pp = &slot->prepare_certificate.pre_prepare;
      else
	pp = &slot->complete_pre_prepare;

      if(APPLY_Commit_Matches_Pre_Prepare(commit_src[sn], pp)) {
	slot->commit_certificate.commit[sn] = commit_src[sn];
	commit_src[sn] = NULL;
      } else {
	Alarm(EXIT, "Commit didn't match pre-prepare while "
	      "moving commit certificate.\n");
	return;
      }
    }
  }

  /* The next time that we process a commit, we should execute. */
  slot->execute_commit = 1;
  slot->ordered = 1;
}

void APPLY_RTT_Ping    (signed_message *mess) {

}

void APPLY_RTT_Pong    (signed_message *mess) {

}

void APPLY_RTT_Measure (signed_message *mess) {
    rtt_measure_message *measure = (rtt_measure_message*)(mess + 1);
    double delta = (double)PRE_PREPARE_SEC + (double)(PRE_PREPARE_USEC)/1000000.0;
    double t = measure->rtt * VARIABILITY_KLAT + delta;
    //printf("tats_if_leader %f %f %d\n", measure->rtt, t, mess->machine_id);
    if (mess->machine_id != VAR.My_Server_ID && t < DATA.SUS.tats_if_leader[mess->machine_id]) {
	DATA.SUS.tats_if_leader[mess->machine_id] = t;
    }
}

void APPLY_TAT_Measure (signed_message *mess) {
    double tats[NUM_SERVER_SLOTS];
    int i;

    tat_measure_message *measure = (tat_measure_message*)(mess + 1);
    if (measure->max_tat > DATA.SUS.reported_tats[mess->machine_id]) {
	DATA.SUS.reported_tats[mess->machine_id] = measure->max_tat;
    }

    for (i = 1; i <= NUM_SERVERS; i++) {
	tats[i] = DATA.SUS.reported_tats[i];
    }
    //printf("tat_leader %f %f %f %f\n", tats[1], tats[2], tats[3], tats[4]);
    qsort((void*)(tats+1), NUM_SERVERS, sizeof(double), doublecmp);

    DATA.SUS.tat_leader = tats[VAR.Faults + 1];
}

void APPLY_TAT_UB (signed_message *mess) {
    double tats[NUM_SERVER_SLOTS];
    int i;

    tat_upper_bound_message *ub = (tat_upper_bound_message*)(mess + 1);
    if (/*mess->machine_id != VAR.My_Server_ID &&*/ ub->alpha < DATA.SUS.tat_leader_ubs[mess->machine_id]) {
	//printf("alpha lower %f\n", ub->alpha);
	DATA.SUS.tat_leader_ubs[mess->machine_id] = ub->alpha;
    }

    for (i = 1; i <= NUM_SERVERS; i++) {
	tats[i] = DATA.SUS.tat_leader_ubs[i];
    }
    ///viprintf("tat_acceptable %f %f %f %f\n", tats[1], tats[2], tats[3], tats[4]);
    qsort((void*)(tats+1), NUM_SERVERS, sizeof(double), doublecmp);

    DATA.SUS.tat_acceptable = tats[NUM_SERVER_SLOTS - (VAR.Faults + 1)];
}

void APPLY_New_Leader (signed_message *mess) {
    //Alarm(PRINT, "Applying new leader\n");
    new_leader_message *new_leader = (new_leader_message*)(mess+1);
    signed_message *leader;
    new_leader_message *leader_specific;
    int32u view = 1;

    leader = DATA.SUS.new_leader[mess->machine_id];
    if (leader != NULL) {
	leader_specific = (new_leader_message*)(leader+1);
	view = leader_specific->new_view;
	if (new_leader->new_view <= view) {
	    return;
	}
	dec_ref_cnt(leader);
    }

    signed_message *copy = new_ref_cnt(PACK_BODY_OBJ);
    if (copy == NULL) {
	Alarm(EXIT, "Apply_New_Leader: could not allocate space for message\n");
    }
    memcpy(copy, mess, UTIL_Message_Size(mess));
    inc_ref_cnt(copy);
    DATA.SUS.new_leader[copy->machine_id] = copy;


    if (DATA.View >= new_leader->new_view) {
	return;
    }

    int32u count = 0;

    int i;
    for (i = 1; i <= NUM_SERVERS; i++) {
	if (DATA.SUS.new_leader[i] == NULL) {
	    continue;
	}
	leader = DATA.SUS.new_leader[i];
	leader_specific = (new_leader_message*)(leader+1);
	view = leader_specific->new_view;
	if (new_leader->new_view == view) {
	    count++;
	}
    }

    if (count > VAR.Faults) {
	DATA.SUS.new_leader_count = count;

	//if 2f+1 received, preinstall next view
	if (DATA.SUS.new_leader_count > 2*VAR.Faults) {
	    Alarm(PRINT, "view change from %d to %d\n", DATA.View, new_leader->new_view);
	    DATA.View = new_leader->new_view;
	    if(DATA.recovery_in_progress == 0 && DATA.buffering_during_recovery == 0)
              DATA.preinstall = 1;
	    DATA.SUS.sent_proof = 0;
            if (UTIL_I_Am_Leader()) {
                Alarm(PRINT, "I AM THE NEW LEADER\n\n");
            }
            else {
                Alarm(PRINT, "New leader = %d\n\n", UTIL_Leader());
            }
	}
    }
}

void APPLY_New_Leader_Proof (signed_message *mess) {
    Alarm(DEBUG, "Applying new leader proof from %d\n", mess->machine_id);
    new_leader_proof_message* new_leader_proof = (new_leader_proof_message*)(mess+1);

    signed_message *new_leader = (signed_message*)(new_leader_proof+1);
    int count = 0;

    while (count < 2*VAR.Faults+1) {
	APPLY_New_Leader(new_leader);
	new_leader = (signed_message*)((char*)new_leader + UTIL_Message_Size(new_leader));
	count++;
    }
}

void APPLY_RB_Init (signed_message *mess) {
    signed_message *payload = (mess+1);
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(payload+1);
    int i;

    DATA.REL.seq_num[payload->machine_id] = rb_tag->seq_num;
    DATA.REL.rb_step[payload->machine_id] = 1;
    //DATA.REL.rb_init[payload->machine_id] = mess;
    //inc_ref_cnt(mess);
    for (i = 1; i <= NUM_SERVERS; ++i) {
	DATA.REL.rb_echo[payload->machine_id][i] = 0;
	DATA.REL.rb_ready[payload->machine_id][i] = 0;
    }
}

void APPLY_RB_Echo (signed_message *mess) {
    signed_message *payload = (mess+1);
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(payload+1);
    int i;

    if (DATA.REL.seq_num[payload->machine_id] < rb_tag->seq_num) {
	DATA.REL.seq_num[payload->machine_id] = rb_tag->seq_num;
	DATA.REL.rb_step[payload->machine_id] = 1;
	//DATA.REL.rb_init[payload->machine_id] = mess;
	//inc_ref_cnt(mess);
	for (i = 1; i <= NUM_SERVERS; ++i) {
	    DATA.REL.rb_echo[payload->machine_id][i] = 0;
	    DATA.REL.rb_ready[payload->machine_id][i] = 0;
	}
    }
    DATA.REL.rb_echo[payload->machine_id][mess->machine_id] = 1;
}

void APPLY_RB_Ready (signed_message *mess) {
    signed_message *payload = (mess+1);
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(payload+1);
    int i;

    if (DATA.REL.seq_num[payload->machine_id] < rb_tag->seq_num) {
	DATA.REL.seq_num[payload->machine_id] = rb_tag->seq_num;
	DATA.REL.rb_step[payload->machine_id] = 1;
	//DATA.REL.rb_init[payload->machine_id] = mess;
	//inc_ref_cnt(mess);
	for (i = 1; i <= NUM_SERVERS; ++i) {
	    DATA.REL.rb_echo[payload->machine_id][i] = 0;
	    DATA.REL.rb_ready[payload->machine_id][i] = 0;
	}
    }
    DATA.REL.rb_ready[payload->machine_id][mess->machine_id] = 1;
}

void APPLY_Report (signed_message *mess) {
    report_message *report = (report_message*)(mess+1);

    memcpy(&DATA.VIEW.report[mess->machine_id], report, sizeof(report_message));
    DATA.VIEW.received_report[mess->machine_id] = 1;
    if (DATA.VIEW.executeTo < report->execARU) {
	DATA.VIEW.executeTo = report->execARU;
	ord_slot *slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU+1);
	if (slot != NULL) {
	    //Alarm(PRINT, "apply report execute commit\n", slot->seq_num);
	    ORDER_Execute_Commit(slot);
	}
    }
    if (report->pc_set_size == 0 && DATA.ORD.ARU >= report->execARU) {
	UTIL_Bitmap_Set(&DATA.VIEW.complete_state, mess->machine_id);
    }
}

void APPLY_PC_Set (signed_message *mess) {
    //pc_set_message *pc_set = (pc_set_message*)(mess+1);
    //TODO: Should we check to make sure each pc is distinct?
    Alarm(DEBUG, "Applying PC_Set %d %d\n", mess->machine_id, DATA.VIEW.pc_set[mess->machine_id]);
    report_message *report = &DATA.VIEW.report[mess->machine_id];
    UTIL_DLL_Add_Data(&DATA.VIEW.pc_set[mess->machine_id], mess);
    //Alarm(PRINT, "done add data %d\n", DATA.VIEW.pc_set[mess->machine_id].length);

    if (report->pc_set_size == DATA.VIEW.pc_set[mess->machine_id].length && DATA.ORD.ARU >= report->execARU) {
	UTIL_Bitmap_Set(&DATA.VIEW.complete_state, mess->machine_id);
    }
    //Alarm(PRINT, "Done applying pc_set\n");
}

void APPLY_VC_List (signed_message *mess) {
    Alarm(DEBUG, "Applying VC List %d\n", DATA.VIEW.sent_vc_partial_sig[1]);
    vc_list_message *vc_list = (vc_list_message*)(mess+1);
    DATA.VIEW.received_vc_list[mess->machine_id] = 1;
    memcpy(&DATA.VIEW.vc_list[mess->machine_id], vc_list, mess->len);
}

void APPLY_VC_Partial_Sig (signed_message *mess) {
    vc_partial_sig_message *vc_partial_sig = (vc_partial_sig_message*)(mess+1);
    int i;
    for (i = 0; i < NUM_SERVERS; ++i) {
	if (DATA.VIEW.received_vc_partial_sig[mess->machine_id][i] == 0) {
	    DATA.VIEW.received_vc_partial_sig[mess->machine_id][i] = 1;
	    memcpy(&DATA.VIEW.vc_partial_sig[mess->machine_id][i], vc_partial_sig, sizeof(vc_partial_sig_message));
	    break;
	}
    }
}

void APPLY_VC_Proof (signed_message *mess) {

}

void APPLY_Replay (signed_message *mess) {
    if (DATA.VIEW.replay == NULL) {
	inc_ref_cnt(mess);
	DATA.VIEW.replay = mess;
    }

    int32u i;
    int32u count = 1;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	if (DATA.VIEW.replay_prepare[i] != NULL) {
	    count++;
	}
    }
    if (count >= 2*VAR.Faults) {
	DATA.VIEW.prepare_ready = 1;
    }
}

void APPLY_Replay_Prepare (signed_message *mess) {
    if (DATA.VIEW.replay_prepare[mess->machine_id] == NULL) {
	inc_ref_cnt(mess);
	DATA.VIEW.replay_prepare[mess->machine_id] = mess;
    }
    int32u i;
    int32u count = 0;
    if (DATA.VIEW.replay != NULL) {
	count++;
    }
    for (i = 1; i <= NUM_SERVERS; ++i) {
	if (DATA.VIEW.replay_prepare[i] != NULL) {
	    count++;
	}
    }
    if (count > 2*VAR.Faults) {
	DATA.VIEW.prepare_ready = 1;
    }
}

void APPLY_Replay_Commit (signed_message *mess) {
    if (DATA.VIEW.replay_commit[mess->machine_id] == NULL) {
	inc_ref_cnt(mess);
	DATA.VIEW.replay_commit[mess->machine_id] = mess;
    }
    int32u i;
    int32u count = 0;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	if (DATA.VIEW.replay_commit[i] != NULL) {
	    count++;
	}
    }
    if (DATA.VIEW.prepare_ready && count > 2*VAR.Faults) {
	DATA.VIEW.commit_ready = 1;
    }
}

void APPLY_Recon(signed_message *recon)
{
  int32u i;
  recon_message *r;
  recon_part_header *rph;
  erasure_part *part;
  recon_slot *slot;
  po_slot *po_slot;
  char *p;
  int32u *ip;
  int32u index;

  r = (recon_message *)(recon + 1);
  p = (char *)(r + 1);

  for(i = 0; i < r->num_parts; i++) {

    rph  = (recon_part_header *)p;
    part = (erasure_part *)(rph + 1);

    /* If we've already contiguously collected PO-Requests for this or higher,
     * then we must already have it. Or if I've already garbage collected
     * this one, I must have it already*/
    if(rph->seq_num <= DATA.PO.aru[rph->originator] ||
       rph->seq_num <= DATA.PO.white_line[rph->originator]) {

      Alarm(DEBUG, "Discarding Recon for %d %d from %d\n",
	    rph->originator, rph->seq_num, recon->machine_id);

      /* Move to the next part and continue */
      p = (char *)part;
      p += rph->part_len;
      continue;
    }

    /* Even though I haven't collected contiguously, I may have the PO
     * request being reconciled.  Skip it in this case. */
    po_slot = UTIL_Get_PO_Slot_If_Exists(rph->originator, rph->seq_num);
    if(po_slot && po_slot->po_request) {
      /* Move to the next part and continue */
      p = (char *)part;
      p += rph->part_len;
      continue;
    }
    
    /* We want to process this part.  Store a copy of it in the slot if
     * we need it. */
    slot = UTIL_Get_Recon_Slot(rph->originator, rph->seq_num);

    /* If we've already decoded this one, continue */
    if(slot->decoded) {
      p = (char *)part;
      p += rph->part_len;
      Alarm(DEBUG, "Ignoring part for %d %d, already decoded\n",
	    rph->originator, rph->seq_num);
      continue;
    }

    if(slot->part_collected[recon->machine_id] == 0) {

      /* Mark that we have the part from this server */
      slot->part_collected[recon->machine_id] = 1;
      slot->num_parts_collected++;
      
      Alarm(DEBUG, "Stored Local Recon for (%d, %d) from %d\n", 
	    rph->originator, rph->seq_num, recon->machine_id);

      /* Copy the part into the buffer */
      memcpy(slot->parts[recon->machine_id], part, rph->part_len);
      
      ip = (int32u *)(part + 1);
      index = ip[0];
      Alarm(DEBUG, "Part had index %d\n", index);

      /* If we have enough parts, we should decode */
      if(slot->num_parts_collected == (VAR.Faults + 1))
	slot->should_decode = 1;

      /* Move on to the next one */
      p = (char *)part;
      p += rph->part_len;
    }
  }
}
