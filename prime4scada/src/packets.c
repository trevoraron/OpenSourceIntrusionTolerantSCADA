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

#include <string.h>
#include <assert.h>
#include "spu_alarm.h"
#include "spu_memory.h"
#include "packets.h"
#include "utility.h"
#include "data_structs.h"
#include "merkle.h"
#include "validate.h"
#include "recon.h"

extern server_data_struct DATA; 
extern server_variables   VAR;
extern benchmark_struct   BENCH;

signed_message* PRE_ORDER_Construct_PO_Request()
{
  signed_message *po_request;
  po_request_message *po_request_specific;
  int32u bytes, this_mess_len, num_events, wa_bytes, cutoff;
  signed_message *mess;
  char *p;

  /* Construct new message */
  po_request          = UTIL_New_Signed_Message();
  po_request_specific = (po_request_message *)(po_request + 1);

  /* Fill in the message based on the event. We construct a message
   * that contains the event by copying the event (which may or may
   * not be a signed message) into the PO Request message. */
  
  po_request->machine_id       = VAR.My_Server_ID;
  po_request->type             = PO_REQUEST;
  po_request_specific->seq_num = DATA.PO.po_seq_num++;

  /* We'll be adding to at least this many bytes */
  bytes = sizeof(signed_message) + sizeof(po_request_message);
  
  num_events = 0;

  /* When we copy, we'll be starting right after the PO request */
  p = (char *)(po_request_specific+1);
  
  cutoff = PRIME_MAX_PACKET_SIZE - (DIGEST_SIZE * MAX_MERKLE_DIGESTS);

  while(bytes < cutoff) {

    wa_bytes = 0;

    /* If there are no more messages, stop. Otherwise grab one and see
     * if it will fit. */
    if((mess = UTIL_DLL_Front_Message(&DATA.PO.po_request_dll)) == NULL)
      break;

    this_mess_len = mess->len + sizeof(signed_message) + wa_bytes;

    if((bytes + this_mess_len) < cutoff) {
      num_events++;
      bytes += this_mess_len;

      /* Copy it into the packet */
      memcpy(p, mess, this_mess_len);
      p += this_mess_len;

      UTIL_DLL_Pop_Front(&DATA.PO.po_request_dll);
    }
    else {
      Alarm(DEBUG, "Won't fit: this_mess_len = %d, type = %d, wa = %d\n", 
	    this_mess_len, mess->type, wa_bytes);
      break;
    }
  }

  po_request_specific->num_events = num_events;

  /* Subtract sizeof(signed_message) because even though we send out
   * that many bytes, the len field is just the content, not the signed
   * message part. */
  po_request->len = bytes - sizeof(signed_message);
  
  BENCH.num_po_requests_sent++;
  BENCH.total_updates_requested += num_events;

  return po_request;
}

signed_message* PRE_ORDER_Construct_PO_Ack(int32u *more_to_ack)
{
  signed_message *po_ack;
  po_ack_message *po_ack_specific;
  po_ack_part *ack_part;
  int32u nparts;
  int32u sm, i;
  po_slot *slot;
  int32u po_request_len;

  /* Construct new message */
  po_ack          = UTIL_New_Signed_Message();
  po_ack_specific = (po_ack_message*)(po_ack + 1);
  
  po_ack->machine_id = VAR.My_Server_ID;
  po_ack->type       = PO_ACK;
  
  /* we must ack all of the unacked po request messages, received
   * contiguously */
  
  ack_part = (po_ack_part*)(po_ack_specific+1);
  
  nparts     = 0;
  
  for(sm = 1; sm <= NUM_SERVERS; sm++) {
    
    assert(DATA.PO.max_acked[sm] <= DATA.PO.aru[sm]);
    
    for(i = DATA.PO.max_acked[sm]+1; i <= DATA.PO.aru[sm]; i++) {
      DATA.PO.max_acked[sm] = i;
      slot = UTIL_Get_PO_Slot_If_Exists(sm, i);
      
      if(slot == NULL) {
	/* We received a PO-Request but decided not to ack yet due to 
	 * aggregation.  Then we order the PO-Request using acks from 
	 * the other servers.  Now we're ready to send the ack but we've
	 * already garbage collected!  This is ok.  Just pretend like
	 * we're acking; everyone else will execute eventually. */
	Alarm(DEBUG, "Continuing locally on %d %d\n", sm, i);
	assert(DATA.PO.white_line[sm] >= i);
	continue;
      }
  
#if RECON_ATTACK
      /* Faulty servers don't ack anyone else's stuff */
      if (UTIL_I_Am_Faulty() && sm > NUM_FAULTS)
	continue;
#endif

      /* Create the ack_part */
      ack_part[nparts].originator = sm;
      ack_part[nparts].seq_num    = i;
      
      /* Modified this.  Includes possible appended digest bytes and
       * does not subtract the signature_size. */
      po_request_len = (sizeof(signed_message) + slot->po_request->len +
			MT_Digests_(slot->po_request->mt_num) * DIGEST_SIZE);

      /* Now compute the digest of the event and copy it into the
       * digest field */
      OPENSSL_RSA_Make_Digest((byte *)(slot->po_request), po_request_len,
			      ack_part[nparts].digest);      
      nparts++;

      if(nparts == MAX_ACK_PARTS)
	goto finish;
    }
  }
  
 finish:

  po_ack_specific->num_ack_parts = nparts;
  
  if (nparts == 0) {
    /* There is nothing in the ack -- we will not send it */
    *more_to_ack = 0;
    dec_ref_cnt( po_ack );
    return NULL;
  }

  if (nparts > MAX_ACK_PARTS) { 
    Alarm(EXIT,"%d BIG LOCAL ACK nparts = %d\n", VAR.My_Server_ID, nparts); 
  }

  po_ack->len = (sizeof(po_ack_message) + 
		 sizeof(po_ack_part) * po_ack_specific->num_ack_parts);
  
  if(nparts == MAX_ACK_PARTS) {
    Alarm(DEBUG, "There may be more to ack!\n");
    *more_to_ack = 1;
  }
  else {
    *more_to_ack = 0;
    Alarm(DEBUG, "Acked %d parts\n", nparts);
  }
  
  BENCH.num_po_acks_sent++;
  BENCH.num_acks += nparts;

  return po_ack;
}

signed_message* PRE_ORDER_Construct_PO_ARU()
{
  int32u s;
  signed_message *po_aru;
  po_aru_message *po_aru_specific;

  /* Construct new message */
  po_aru          = UTIL_New_Signed_Message();
  po_aru_specific = (po_aru_message*)(po_aru + 1);

  po_aru->machine_id = VAR.My_Server_ID;

  po_aru->type       = PO_ARU;
  po_aru->len        = sizeof(po_aru_message);
  
  po_aru_specific->num = DATA.PO.po_aru_num;
  DATA.PO.po_aru_num++;

  /* Fill in vector of cumulative pre order acks */

  for (s = 0; s < NUM_SERVERS; s++)
    po_aru_specific->ack_for_server[s] = DATA.PO.cum_aru[s+1];

#if 0
  /* Compute a standard RSA signature. */
  Alarm(PRINT, "Signature: Local PO-ARU\n");
  UTIL_RSA_Sign_Message(po_aru);
#endif  

  return po_aru;
}

void PRE_ORDER_Construct_Proof_Matrix(signed_message **mset,
				      int32u *num_parts)
{
  signed_message *mess;
  proof_matrix_message *pm_specific;
  int32u total_parts, i, index, length;

  /* TODO: MAKE THIS GENERIC FOR ANY f */
  if(NUM_FAULTS == 1)
    total_parts = 1;
  else
    total_parts = 2;
  
  for(i = 1; i <= total_parts; i++) {
    mset[i] = UTIL_New_Signed_Message();
    mess    = (signed_message *)mset[i];

    mess->type       = PROOF_MATRIX;
    mess->machine_id = VAR.My_Server_ID;
    mess->len        = 0; /* Set below */

    pm_specific      = (proof_matrix_message *)(mess+1);

    if(NUM_FAULTS == 1)
      pm_specific->num_acks_in_this_message = 4;
    else {
      if(i == 1)
	pm_specific->num_acks_in_this_message = (3*NUM_FAULTS+1) / 2;
      else
	pm_specific->num_acks_in_this_message = ((3*NUM_FAULTS+1) - 
						 ((3*NUM_FAULTS+1)/2));
    }
  }

  index = 1;
  for(i = 1; i <= total_parts; i++) {
    pm_specific = (proof_matrix_message *)(mset[i] + 1);
    length      = (sizeof(po_aru_signed_message) * 
		   pm_specific->num_acks_in_this_message);
    
    memcpy((byte *)(pm_specific + 1), (byte *)(DATA.PO.cum_acks+index),
	 length);
    mset[i]->len = sizeof(proof_matrix_message) + length;
    index += pm_specific->num_acks_in_this_message;
  }

  *num_parts = total_parts;
}

void ORDER_Construct_Pre_Prepare(signed_message **mset,int32u *num_parts)
{
  signed_message *mess;
  pre_prepare_message *pp_specific;
  int32u total_parts, i, index, length;

  /* TODO: MAKE THIS GENERIC FOR ANY f */
  if(NUM_FAULTS == 1)
    total_parts = 1;
  else
    total_parts = 2;

  for(i = 1; i <= total_parts; i++) {
    mset[i] = UTIL_New_Signed_Message();
    mess    = (signed_message *)mset[i];

    mess->type       = PRE_PREPARE;
    mess->machine_id = VAR.My_Server_ID;
    mess->len        = 0; /* Set below */

    pp_specific              = (pre_prepare_message *)(mess+1);
    pp_specific->seq_num     = DATA.ORD.seq;
    //Alarm(PRINT, "pre-prepare seq %d\n", DATA.ORD.seq);
    pp_specific->view        = DATA.View;
    pp_specific->part_num    = i;
    pp_specific->total_parts = total_parts;

    if(NUM_FAULTS == 1)
      pp_specific->num_acks_in_this_message = 4;
    else {
      if(i == 1)
	pp_specific->num_acks_in_this_message = (3*NUM_FAULTS+1) / 2;
      else
	pp_specific->num_acks_in_this_message = ((3*NUM_FAULTS+1) - 
						 ((3*NUM_FAULTS+1)/2));
    }
  }
  
  index = 1;
  for(i = 1; i <= total_parts; i++) {
    pp_specific = (pre_prepare_message *)(mset[i] + 1);
    length      = (sizeof(po_aru_signed_message) * 
		   pp_specific->num_acks_in_this_message);

    memcpy((byte *)(pp_specific + 1), (byte *)(DATA.PO.cum_acks+index),
	   length);
    mset[i]->len = sizeof(pre_prepare_message) + length;
    index += pp_specific->num_acks_in_this_message;
  }
  
  DATA.ORD.seq++;
  *num_parts = total_parts;
}

signed_message* ORDER_Construct_Prepare(complete_pre_prepare_message *pp)
{
  signed_message *prepare;
  prepare_message *prepare_specific;

  /* Construct new message */
  prepare          = UTIL_New_Signed_Message();
  prepare_specific = (prepare_message *)(prepare + 1);

  prepare->machine_id = VAR.My_Server_ID;
  prepare->type       = PREPARE;
  prepare->len        = sizeof(prepare_message);
    
  prepare_specific->seq_num = pp->seq_num;
  prepare_specific->view    = pp->view;
  
  /* Now compute the digest of the content and copy it into the digest field */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), prepare_specific->digest);
  
  return prepare;
}

signed_message *ORDER_Construct_Commit(complete_pre_prepare_message *pp)
{
  signed_message *commit;
  commit_message *commit_specific;
  
  /* Construct new message */
  commit          = UTIL_New_Signed_Message();
  commit_specific = (commit_message*)(commit + 1);

  commit->machine_id = VAR.My_Server_ID;
  commit->type       = COMMIT;
  commit->len        = sizeof(commit_message);

  commit_specific->seq_num = pp->seq_num;
  commit_specific->view    = pp->view;
  
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), commit_specific->digest);

  return commit;
}

signed_message *ORDER_Construct_Client_Response(int32u client_id, 
						int32u seq_num, int32u message_type,
                                                int32u client_seq_num, 
                                                byte content[UPDATE_SIZE])
{
  signed_message *response;
  client_response_message *response_specific;
  byte *buf;

  /* Construct new message */
  response = UTIL_New_Signed_Message();

  response_specific = (client_response_message*)(response + 1);

  response->machine_id = VAR.My_Server_ID;
  response->type       = CLIENT_RESPONSE;
  response->len        = sizeof(client_response_message) + UPDATE_SIZE;

  response_specific->machine_id = client_id;
  response_specific->seq_num    = seq_num;
  response_specific->recovery   = 0;

  //Set a flag if the current replica is doing recovery
  if(DATA.recovery_in_progress || DATA.buffering_during_recovery)
    response_specific->recovery = 1;

  response_specific->message_type = message_type;
  response_specific->client_seq_num = client_seq_num;
  buf = (byte *)(response_specific + 1);
  memcpy( buf, content, 2 * sizeof(unsigned int) );

  return response;
}

signed_message *SUSPECT_Construct_RTT_Ping()
{
  signed_message *ping;
  rtt_ping_message *ping_specific;

  /* Construct new message */
  ping = UTIL_New_Signed_Message();

  ping_specific = (rtt_ping_message*)(ping + 1);

  ping->machine_id = VAR.My_Server_ID;
  ping->type       = RTT_PING;
  ping->len        = sizeof(rtt_ping_message);

  ping_specific->ping_seq_num = DATA.SUS.ping_seq_num;
  ping_specific->view    = DATA.View;

  return ping;
}


signed_message *SUSPECT_Construct_RTT_Pong(int32u server_id, int32u seq_num)
{
  signed_message *pong;
  rtt_pong_message *pong_specific;

  /* Construct new message */
  pong = UTIL_New_Signed_Message();

  pong_specific = (rtt_pong_message*)(pong + 1);

  pong->machine_id = VAR.My_Server_ID;
  pong->type       = RTT_PONG;
  pong->len        = sizeof(rtt_pong_message);

  pong_specific->ping_seq_num = seq_num;
  pong_specific->view    = DATA.View;
  pong_specific->recipient = server_id;

  return pong;
}

signed_message *SUSPECT_Construct_RTT_Measure(int32u server_id, double rtt)
{
  signed_message *measure;
  rtt_measure_message *measure_specific;

  /* Construct new message */
  measure = UTIL_New_Signed_Message();

  measure_specific = (rtt_measure_message*)(measure + 1);

  measure->machine_id = VAR.My_Server_ID;
  measure->type       = RTT_MEASURE;
  measure->len        = sizeof(rtt_measure_message);

  measure_specific->rtt = rtt;
  measure_specific->view = DATA.View;
  measure_specific->recipient = server_id;

  return measure;
}

signed_message *SUSPECT_Construct_TAT_Measure(double max_tat)
{
  signed_message *measure;
  tat_measure_message *measure_specific;

  /* Construct new message */
  measure = UTIL_New_Signed_Message();

  measure_specific = (tat_measure_message*)(measure + 1);

  measure->machine_id = VAR.My_Server_ID;
  measure->type       = TAT_MEASURE;
  measure->len        = sizeof(tat_measure_message);

  measure_specific->max_tat = max_tat;
  measure_specific->view = DATA.View;

  return measure;
}

signed_message *SUSPECT_Construct_TAT_UB(double alpha)
{
  signed_message *ub;
  tat_upper_bound_message *ub_specific;

  /* Construct new message */
  ub = UTIL_New_Signed_Message();

  ub_specific = (tat_upper_bound_message*)(ub + 1);

  ub->machine_id = VAR.My_Server_ID;
  ub->type       = TAT_UB;
  ub->len        = sizeof(tat_upper_bound_message);

  ub_specific->alpha = alpha;
  ub_specific->view = DATA.View;

  return ub;
}

signed_message *SUSPECT_Construct_New_Leader()
{
  signed_message *new_leader;
  new_leader_message *new_leader_specific;

  /* Construct new message */
  new_leader = UTIL_New_Signed_Message();

  new_leader_specific = (new_leader_message*)(new_leader + 1);

  new_leader->machine_id = VAR.My_Server_ID;
  new_leader->type       = NEW_LEADER; 
  new_leader->len        = sizeof(new_leader_message);

  new_leader_specific->new_view = DATA.View + 1;

  return new_leader;
}

signed_message *SUSPECT_Construct_New_Leader_Proof()
{
    signed_message *new_leader_proof;
    new_leader_proof_message *new_leader_proof_specific;
    char *ptr;
    new_leader_message *new_leader;

    /* Construct new message */
    new_leader_proof = UTIL_New_Signed_Message();

    new_leader_proof_specific = (new_leader_proof_message*)(new_leader_proof + 1);

    new_leader_proof->machine_id = VAR.My_Server_ID;
    new_leader_proof->type       = NEW_LEADER_PROOF; 
    new_leader_proof->len        = sizeof(new_leader_proof_message);

    new_leader_proof_specific->new_view = DATA.View; //is already new view (but only preinstalled)
    //Alarm(PRINT, "creating new leader proof view %d\n", DATA.View);

    ptr = (char*)(new_leader_proof_specific+1);
    int count = 0;
    int i = 1;
    while (count < 2*VAR.Faults+1 && i <= NUM_SERVERS) {
	if (DATA.SUS.new_leader[i] != NULL && DATA.SUS.new_leader[i]->type == NEW_LEADER) {
	    new_leader = (new_leader_message*)(DATA.SUS.new_leader[i]+1);
	    if(new_leader->new_view == DATA.View) {
		int32u size = UTIL_Message_Size(DATA.SUS.new_leader[i]);
		//Alarm(PRINT, "copying new leader into %x id %d view %d size %d\n", ptr, i, new_leader->new_view, size);
		memcpy(ptr, DATA.SUS.new_leader[i], size);
		count++;
		ptr = ptr + size;
		new_leader_proof->len += size;
	    }
	}
	//Alarm(PRINT, "i %d, count %d %d\n", i, count, DATA.SUS.new_leader_count);
	i++;
    }
    //Alarm(PRINT, "size %d\n", new_leader_proof->len);

    return new_leader_proof;
}

signed_message* RELIABLE_Construct_RB_Init(signed_message *mess) {
  signed_message *rb_init;
  signed_message *payload;

  int32u size = sizeof(signed_message)+mess->len;
  /* Construct new message */
  rb_init = UTIL_New_Signed_Message();

  rb_init->machine_id = VAR.My_Server_ID;
  rb_init->type       = RB_INIT; 
  rb_init->len        = size;

  payload = (signed_message*)(rb_init + 1);
  memcpy(payload, (void*)mess, size);

  return rb_init;
}

signed_message* RELIABLE_Construct_RB_Echo(signed_message *mess) {
  signed_message *rb_echo;
  signed_message *payload;
  int32u size = sizeof(signed_message)+mess->len;

  /* Construct new message */
  rb_echo = UTIL_New_Signed_Message();

  rb_echo->machine_id = VAR.My_Server_ID;
  rb_echo->type       = RB_ECHO; 
  rb_echo->len        = size;

  payload = (signed_message*)(rb_echo + 1);
  memcpy(payload, (void*)mess, size);

  return rb_echo;
}

signed_message* RELIABLE_Construct_RB_Ready(signed_message *mess) {
  signed_message *rb_ready;
  signed_message *payload;
  int32u size = sizeof(signed_message)+mess->len;

  /* Construct new message */
  rb_ready = UTIL_New_Signed_Message();

  rb_ready->machine_id = VAR.My_Server_ID;
  rb_ready->type       = RB_READY; 
  rb_ready->len        = size;

  payload = (signed_message*)(rb_ready + 1);
  memcpy(payload, (void*)mess, size);

  return rb_ready;
}

signed_message* VIEW_Construct_Report(void) {
  signed_message *report;
  report_message *report_specific;

  /* Construct new message */
  report = UTIL_New_Signed_Message();

  report_specific = (report_message*)(report + 1);

  report->machine_id = VAR.My_Server_ID;
  report->type       = REPORT; 
  report->len        = sizeof(report_message);

  report_specific->execARU = DATA.ORD.ARU;
  report_specific->pc_set_size = DATA.VIEW.numSeq;
  return report;
}

signed_message* VIEW_Construct_PC_Set(char *cert, int size) {
  signed_message *pc_set;
  pc_set_message *pc_set_specific;

  /* Construct new message */
  pc_set = UTIL_New_Signed_Message();

  pc_set_specific = (pc_set_message*)(pc_set + 1);

  pc_set->machine_id = VAR.My_Server_ID;
  pc_set->type       = PC_SET; 
  pc_set->len        = sizeof(pc_set_message)+size;

  char *ptr = (char*)(pc_set_specific+1);

  memcpy(ptr, cert, size);

  return pc_set;
}

signed_message* VIEW_Construct_VC_List(void) {
  signed_message *vc_list;
  vc_list_message *vc_list_specific;

  /* Construct new message */
  vc_list = UTIL_New_Signed_Message();

  vc_list_specific = (vc_list_message*)(vc_list + 1);

  vc_list->machine_id = VAR.My_Server_ID;
  vc_list->type       = VC_LIST; 
  vc_list->len        = sizeof(vc_list_message);

  vc_list_specific->view = DATA.View;
  
  vc_list_specific->complete_state = DATA.VIEW.complete_state;

  return vc_list;
}

signed_message* VIEW_Construct_VC_Partial_Sig(int32u ids) {
  signed_message *vc_partial_sig;
  vc_partial_sig_message *vc_partial_sig_specific;

  /* Construct new message */
  vc_partial_sig = UTIL_New_Signed_Message();

  vc_partial_sig_specific = (vc_partial_sig_message*)(vc_partial_sig + 1);

  vc_partial_sig->machine_id = VAR.My_Server_ID;
  vc_partial_sig->type       = VC_PARTIAL_SIG; 
  vc_partial_sig->len        = sizeof(vc_partial_sig_message);

  vc_partial_sig_specific->view = DATA.View;
  vc_partial_sig_specific->ids = ids;

  int32u startSeq = 0;
  int32u i;
  for (i = 1; i <= NUM_SERVERS; ++i) {

    if (UTIL_Bitmap_Is_Set(&ids, i) && startSeq < DATA.VIEW.report[i].execARU + DATA.VIEW.report[i].pc_set_size + 1) {
	startSeq = DATA.VIEW.report[i].execARU + DATA.VIEW.report[i].pc_set_size + 1;
    }
  }

  vc_partial_sig_specific->startSeq = startSeq;

  byte digest[DIGEST_SIZE];
  OPENSSL_RSA_Make_Digest( 
	  vc_partial_sig_specific, 
	  3*sizeof(int32u), 
	  digest );
  TC_Generate_Sig_Share(vc_partial_sig_specific->thresh_sig, digest); 

  return vc_partial_sig;
}

signed_message* VIEW_Construct_VC_Proof(int32u view, int32u ids, int32u startSeq, byte *sig) {
  signed_message *vc_proof;
  vc_proof_message *vc_proof_specific;

  /* Construct new message */
  vc_proof = UTIL_New_Signed_Message();

  vc_proof_specific = (vc_proof_message*)(vc_proof + 1);

  vc_proof->machine_id = VAR.My_Server_ID;
  vc_proof->type       = VC_PROOF; 
  vc_proof->len        = sizeof(vc_proof_message);

  vc_proof_specific->view = view;
  vc_proof_specific->ids = ids;
  vc_proof_specific->startSeq = startSeq;
  memcpy(vc_proof_specific->thresh_sig, sig, SIGNATURE_SIZE);

  return vc_proof;
}

signed_message* VIEW_Construct_Replay(vc_proof_message *proof) {
  signed_message *replay;
  replay_message *replay_specific;

  /* Construct new message */
  replay = UTIL_New_Signed_Message();

  replay_specific = (replay_message*)(replay + 1);

  replay->machine_id = VAR.My_Server_ID;
  replay->type       = REPLAY; 
  replay->len        = sizeof(replay_message);

  memcpy(&replay_specific->proof, proof, sizeof(vc_proof_message));

  return replay;
}

signed_message* VIEW_Construct_Replay_Prepare(void) {
  signed_message *replay;
  replay_message *replay_specific;

  /* Construct new message */
  replay = UTIL_New_Signed_Message();

  replay_specific = (replay_message*)(replay + 1);

  replay->machine_id = VAR.My_Server_ID;
  replay->type       = REPLAY_PREPARE; 
  replay->len        = sizeof(replay_prepare_message);

  return replay;
}

signed_message* VIEW_Construct_Replay_Commit(void) {
  signed_message *replay;
  replay_message *replay_specific;

  /* Construct new message */
  replay = UTIL_New_Signed_Message();

  replay_specific = (replay_message*)(replay + 1);

  replay->machine_id = VAR.My_Server_ID;
  replay->type       = REPLAY_COMMIT; 
  replay->len        = sizeof(replay_commit_message);

  return replay;
}


signed_message *RECON_Construct_Recon_Erasure_Message(dll_struct *list,
						      int32u *more_to_encode)
{
  signed_message *mess;
  erasure_part *part;
  erasure_part_obj *ep;
  recon_message *r;
  recon_part_header *rph;
  int32u cutoff, bytes;
  char *p;

  mess = UTIL_New_Signed_Message();

  mess->type       = RECON;
  mess->machine_id = VAR.My_Server_ID;
  mess->len        = 0; /* Set below when we add parts */

  r = (recon_message *)(mess + 1);

  r->num_parts = 0; /* Updated as we add parts */

  /* This message may have local Merkle tree digests, and it needs to 
   * fit into a local PO-Request to be ordered, which might have 
   * digests of its own, along with a signed message and a po_request. */
  cutoff = (PRIME_MAX_PACKET_SIZE - (DIGEST_SIZE * MAX_MERKLE_DIGESTS));
  
  bytes = sizeof(signed_message) + sizeof(recon_message);

  /* Start writing parts right after the recon_message */
  p = (char *)(r+1);

  assert(!UTIL_DLL_Is_Empty(list));

  /* Go through as many message on the list as we can.  Encode each one,
   * then write the part you're supposed to send into the packet. */
  while(bytes < cutoff) {
    UTIL_DLL_Set_Begin(list);

    /* If there are no more messages to encode, stop.  Otherwise, grab one, 
     * see if the part will fit in the message, and encode it. */
    if((ep = (erasure_part_obj *)UTIL_DLL_Front_Message(list)) == NULL) {
      *more_to_encode = 0;
      break;
    }    

    if((bytes + sizeof(recon_part_header) + ep->part_len) < cutoff) {

      /* Write the preorder id of the part being encoded */
      rph = (recon_part_header *)p;
      rph->originator = ep->originator;
      rph->seq_num    = ep->seq_num;

      /* Write the length of the part being encoded, including the erasure
       * part, which contains the message length. This is how many bytes
       * follows the rph. */
      rph->part_len = ep->part_len;

      /* Write the part itself right after the header, and write the 
       * length of the message being encoded. */
      part = (erasure_part *)(rph + 1);
      part->mess_len = ep->part.mess_len;
      
      /* Skip past the erasure_part */
      p = (char *)(part+1);
      
      /* Now write the part itself */
      memcpy(p, ep->buf, ep->part_len - sizeof(erasure_part));
      p += (ep->part_len - sizeof(erasure_part));
      
      /* We wrote this many bytes to the packet */
      bytes += sizeof(recon_part_header) + ep->part_len;

      r->num_parts++;
      UTIL_DLL_Pop_Front(list);
    }
    else {
      *more_to_encode = 1;
      break;
    }
  }
  
  assert(bytes <= cutoff);
  assert(r->num_parts > 0);
  mess->len = bytes - sizeof(signed_message);

  return mess;
}

/* Functions for proactive recovery */
signed_message* RECOVERY_Construct_Ord_Cert_Message(int32u sn, int32u v) {

  signed_message   *cert;
  ord_cert_message *cert_specific;
  
  /* Construct new message */
  cert          = UTIL_New_Signed_Message();
  cert_specific = (ord_cert_message*)(cert + 1);

  cert->machine_id = VAR.My_Server_ID;
  cert->type       = ORD_CERT;
  cert->len        = sizeof(ord_cert_message);

  cert_specific->seq_num = sn;
  cert_specific->view    = v;
  
  return cert;
}

signed_message* RECOVERY_Construct_Ord_Cert_Reply_Message(int32u seq_num, int32u view, char *prep, int size, complete_pre_prepare_message pre_prepare) {
  signed_message         *cert_mess;
  ord_cert_reply_message *cert_mess_specific;

  /* Construct new message */
  cert_mess = UTIL_New_Signed_Message();

  cert_mess_specific = (ord_cert_reply_message*)(cert_mess + 1);

  cert_mess->machine_id = VAR.My_Server_ID;
  cert_mess->type       = ORD_CERT_REPLY; 
  cert_mess->len        = sizeof(ord_cert_reply_message) + size;

  cert_mess_specific->seq_num     = seq_num;
  cert_mess_specific->view        = view;
  cert_mess_specific->pre_prepare = pre_prepare;
  
  char *ptr = (char *)(cert_mess_specific + 1);
  memcpy(ptr, prep, size);

  return cert_mess;
}

signed_message* RECOVERY_Construct_PO_Cert_Message(int32u server_id, int32u seq_num) {

  signed_message  *cert;
  po_cert_message *cert_specific;

  /* Construct new message */
  cert          = UTIL_New_Signed_Message();
  cert_specific = (po_cert_message *)(cert + 1);

  cert->machine_id = VAR.My_Server_ID;
  cert->type       = PO_CERT;
  cert->len        = sizeof(po_cert_message);

  cert_specific->server_id = server_id;
  cert_specific->seq_num   = seq_num;

  return cert;
}

signed_message* RECOVERY_Construct_PO_Cert_Reply_Message(int32u server_id, int32u seq_num, char *upd, int32u ack_count, int size) {
  signed_message        *cert_mess;
  po_cert_reply_message *cert_mess_specific;

  /* Construct new message */
  cert_mess = UTIL_New_Signed_Message();

  cert_mess_specific = (po_cert_reply_message*)(cert_mess + 1);

  cert_mess->machine_id = VAR.My_Server_ID;
  cert_mess->type       = PO_CERT_REPLY;
  cert_mess->len        = sizeof(po_cert_reply_message) + size;

  cert_mess_specific->server_id = server_id;
  cert_mess_specific->seq_num   = seq_num;
  cert_mess_specific->ack_count = ack_count;

  char *ptr = (char *)(cert_mess_specific + 1);
  memcpy(ptr, upd, size);

  return cert_mess;
}

signed_message* RECOVERY_Construct_DB_State_Digest_Request_Message(int32u ckpt_id) {
  signed_message                  *mess;
  db_state_digest_request_message *db_state_digest;
    
  /* Construct new message */
  mess            = UTIL_New_Signed_Message();
  db_state_digest = (db_state_digest_request_message *)(mess + 1);
    
  mess->machine_id = VAR.My_Server_ID;
  mess->type       = DB_STATE_DIGEST_REQUEST;
  mess->len        = sizeof(db_state_digest_request_message);
    
  db_state_digest->checkpoint_id = ckpt_id;
    
  return mess;
}

signed_message* RECOVERY_Construct_DB_State_Digest_Reply_Message(int32u ckpt_id, byte digest[], off_t size) {
  signed_message                *mess;
  db_state_digest_reply_message *db_state_digest;
    
  /* Construct new message */
  mess            = UTIL_New_Signed_Message();
  db_state_digest = (db_state_digest_reply_message *)(mess + 1);
    
  mess->machine_id = VAR.My_Server_ID;
  mess->type       = DB_STATE_DIGEST_REPLY;
  mess->len        = sizeof(db_state_digest_reply_message);
    
  db_state_digest->checkpoint_id = ckpt_id;
  db_state_digest->state_size = size;
  memcpy(db_state_digest->digest, digest, DIGEST_SIZE * sizeof(byte));
    
  return mess;
}

signed_message* RECOVERY_Construct_DB_State_Validation_Request_Message(int32u ckpt_id, int32u block) {
  signed_message                      *mess;
  db_state_validation_request_message *db_state_req;

  /* Construct new message */
  mess         = UTIL_New_Signed_Message();
  db_state_req = (db_state_validation_request_message *)(mess + 1);

  mess->machine_id = VAR.My_Server_ID;
  mess->type       = DB_STATE_VALIDATION_REQUEST;
  mess->len        = sizeof(db_state_validation_request_message);

  db_state_req->checkpoint_id = ckpt_id;
  db_state_req->data_block    = block;

  return mess;
}

signed_message* RECOVERY_Construct_DB_State_Validation_Reply_Message(int32u ckpt_id, int32u block, byte digest[]) {
  signed_message                    *mess;
  db_state_validation_reply_message *db_state_reply;

  /* Construct new message */
  mess           = UTIL_New_Signed_Message();
  db_state_reply = (db_state_validation_reply_message *)(mess + 1);

  mess->machine_id = VAR.My_Server_ID;
  mess->type       = DB_STATE_VALIDATION_REPLY;
  mess->len        = sizeof(db_state_validation_reply_message);

  db_state_reply->checkpoint_id = ckpt_id;
  db_state_reply->data_block    = block;
  memcpy(db_state_reply->digest, digest, DIGEST_SIZE * sizeof(byte));

  return mess;
}

signed_message* RECOVERY_Construct_DB_State_Transfer_Request_Message(int32u ckpt_id, int32u block) {
  signed_message                    *mess;
  db_state_transfer_request_message *db_state_req;

  /* Construct new message */
  mess           = UTIL_New_Signed_Message();
  db_state_req   = (db_state_transfer_request_message *)(mess + 1);

  mess->machine_id = VAR.My_Server_ID;
  mess->type       = DB_STATE_TRANSFER_REQUEST;
  mess->len        = sizeof(db_state_transfer_request_message);

  db_state_req->checkpoint_id = ckpt_id;
  db_state_req->data_block    = block;
  
  return mess;
}

signed_message* RECOVERY_Construct_DB_State_Transfer_Reply_Message(int32u ckpt_it, int32u part, int32u block, char* buf, int32u size) {
  signed_message                  *mess;
  db_state_transfer_reply_message *db_state_reply;

  /* Construct new message */
  mess           = UTIL_New_Signed_Message();
  db_state_reply = (db_state_transfer_reply_message *)(mess + 1);

  mess->machine_id = VAR.My_Server_ID;
  mess->type       = DB_STATE_TRANSFER_REPLY;
  mess->len        = sizeof(db_state_transfer_reply_message) + size;

  db_state_reply->checkpoint_id = ckpt_it;
  db_state_reply->part          = part;
  db_state_reply->bytes         = size;
  db_state_reply->data_block    = block; 

  char *ptr = (char *)(db_state_reply + 1);
  memcpy(ptr, buf, size);

  return mess;
}

signed_message* RECOVERY_Construct_Catch_Up_Message() {
  signed_message *mess;

  /* Construct new message */
  mess = UTIL_New_Signed_Message();

  mess->machine_id = VAR.My_Server_ID;
  mess->type       = CATCH_UP;
  mess->len        = sizeof(catch_up_message);

  return mess;
}

signed_message* RECOVERY_Construct_Catch_Up_Reply_Message(int32u view, int32u seq_num, int32u srv_aru[]) {
  signed_message         *mess;
  catch_up_reply_message *catch_up_reply;
  int32u i;

  /* Construct new message */
  mess           = UTIL_New_Signed_Message();
  catch_up_reply = (catch_up_reply_message *)(mess + 1);

  mess->machine_id = VAR.My_Server_ID;
  mess->type       = CATCH_UP_REPLY;
  mess->len        = sizeof(catch_up_reply_message);

  catch_up_reply->view = view;
  catch_up_reply->seq_num = seq_num;
  for(i = 1; i < NUM_SERVER_SLOTS; i++)
    catch_up_reply->aru[i] = srv_aru[i];

  return mess;
}
