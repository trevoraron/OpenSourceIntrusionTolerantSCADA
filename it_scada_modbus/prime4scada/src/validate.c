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

/* Message validation functions. These functions check to make sure messages
 * came from the server or site that should have sent them and check to make
 * sure that the lengths are correct. */

#include "spu_alarm.h"
#include "validate.h"
#include "data_structs.h"
#include "error_wrapper.h"
#include "merkle.h"
#include "openssl_rsa.h"
#include "utility.h"
#include "packets.h"


extern server_variables VAR;
extern server_data_struct DATA;


int32u VAL_Signature_Type         (int32u message_type); 
int32u VAL_Validate_Sender        (int32u sig_type, int32u sender_id); 
int32u VAL_Is_Valid_Signature     (int32u sig_type, int32u sender_id, 
				   int32u site_id, signed_message *mess);

int32u VAL_Validate_Update    (update_message *update, int32u num_bytes); 
int32u VAL_Validate_PO_Request(po_request_message *po_request,
			       int32u num_bytes);
int32u VAL_Validate_PO_Ack      (po_ack_message *po_ack,   int32u num_bytes);
int32u VAL_Validate_PO_ARU      (po_aru_message *po_aru,   int32u num_bytes);
int32u VAL_Validate_Proof_Matrix(proof_matrix_message *pm, int32u num_bytes);
int32u VAL_Validate_Pre_Prepare (pre_prepare_message *pp,  int32u num_bytes);
int32u VAL_Validate_Prepare     (prepare_message *prepare, int32u num_bytes);
int32u VAL_Validate_Commit      (commit_message *commit,   int32u num_bytes);

int32u VAL_Validate_RTT_Ping	(rtt_ping_message *ping,   int32u num_bytes);
int32u VAL_Validate_RTT_Pong	(rtt_pong_message *pong,   int32u num_bytes);
int32u VAL_Validate_RTT_Measure	(rtt_measure_message *measure,   int32u num_bytes);
int32u VAL_Validate_TAT_Measure	(tat_measure_message *measure,   int32u num_bytes);
int32u VAL_Validate_TAT_UB	(tat_upper_bound_message *ub,   int32u num_bytes);
int32u VAL_Validate_New_Leader	(new_leader_message *new_leader,   int32u num_bytes);
int32u VAL_Validate_New_Leader_Proof	(new_leader_proof_message *new_leader,   int32u num_bytes);

int32u VAL_Validate_RB_Init	(signed_message *rb_init,   int32u num_bytes);
int32u VAL_Validate_RB_Echo	(signed_message *rb_echo,   int32u num_bytes);
int32u VAL_Validate_RB_Ready	(signed_message *rb_ready,   int32u num_bytes);

int32u VAL_Validate_VC_List	(vc_list_message *vc_list,   int32u num_bytes);
int32u VAL_Validate_VC_Partial_Sig	(vc_partial_sig_message *vc_partial_sig,   int32u num_bytes);
int32u VAL_Validate_VC_Proof	(vc_proof_message *vc_proof,   int32u num_bytes);

int32u VAL_Validate_Replay	(replay_message *replay,   int32u num_bytes);
int32u VAL_Validate_Replay_Prepare	(replay_prepare_message *replay,   int32u num_bytes);
int32u VAL_Validate_Replay_Commit	(replay_commit_message *replay,   int32u num_bytes);

int32u VAL_Validate_ORD_Cert (ord_cert_message *mess, int32u num_bytes);
int32u VAL_Validate_Retrieved_ORD_Cert (ord_cert_reply_message *mess, int32u num_bytes);
int32u VAL_Validate_PO_Cert (po_cert_message *mess, int32u num_bytes);
int32u VAL_Validate_Retrieved_PO_Cert (po_cert_reply_message *mess, int32u num_bytes);
int32u VAL_Validate_DB_Digest_Request (db_state_digest_request_message *mess, int32u num_bytes);
int32u VAL_Validate_DB_Digest_Reply (db_state_digest_reply_message *mess, int32u num_bytes);
int32u VAL_Validate_DB_Val_Request (db_state_validation_request_message *mess, int32u num_bytes);
int32u VAL_Validate_DB_Val_Reply (db_state_validation_reply_message *mess, int32u num_bytes);
int32u VAL_Validate_DB_State_Tran_Request (db_state_transfer_request_message *mess, int32u num_bytes);
int32u VAL_Validate_Catch_Up(catch_up_message *mess, int32u num_bytes);
int32u VAL_Validate_Catch_Up_Reply(catch_up_reply_message *mess, int32u num_bytes);

/* Determine if a message from the network is valid. */
int32u VAL_Validate_Message(signed_message *message, int32u num_bytes) 
{
  if(DATA.recovery_in_progress == 1)
    return 1;

  byte *content;
  int32u num_content_bytes;
  int32u ret;
 
  /* Since we use Merkle trees, all messages except client updates
   * need to be Merkle-tree verified. */
 
  if (message->type == DUMMY || message->type >= LAST_MESSAGE_TYPE) {
    VALIDATE_FAILURE("Undefined message type");
    return 0;
  }
  if (message->machine_id == 0 || message->machine_id > NUM_SERVERS) {
    VALIDATE_FAILURE("Incorrect machine_id");
    return 0;
  }
  if (message->len + sizeof(signed_message) > PRIME_MAX_PACKET_SIZE) {
    VALIDATE_FAILURE("Message length too long");
    return 0;
  }
  if (message->mt_num > 256 || message->mt_index > message->mt_num) {
      VALIDATE_FAILURE("Merkle tree values set incorrectly");
      return 0;
  }

  if (num_bytes < sizeof(signed_message)) {
    /* Safety check -- should be impossible */
    VALIDATE_FAILURE_LOG(message,num_bytes);
    return 0;
  }
  
  content = (byte*)(message + 1);
  num_content_bytes = num_bytes - sizeof(signed_message) - (MT_Digests_(message->mt_num) * DIGEST_SIZE); /* always >= 0 */

  if (message->len != num_content_bytes) {
    Alarm(DEBUG, "message type %s len %d actual %d\n", UTIL_Type_To_String(message->type), message->len, num_content_bytes);
    VALIDATE_FAILURE("Message length incorrect");
    return 0;
  }

  if(message->type == UPDATE && (CLIENTS_SIGN_UPDATES == 0))
    return 1;

  if (message->type == PO_ARU || message->type == REPORT || message->type == PC_SET) {
      if (message->mt_num > 0 || message->mt_index > 0) {
	  VALIDATE_FAILURE("Merkle tree digests being used on inappropriate message type");
	  return 0;
      }
      if (!VAL_Validate_Signed_Message(message, num_bytes, 1)) {
	  //Alarm(PRINT, "Validate signed message failed.\n");
	  VALIDATE_FAILURE_LOG(message,num_bytes);
	  return 0;
      }
  } else {
      ret = MT_Verify(message);
      if(ret == 0) {
	  Alarm(PRINT, "MT_Verify returned 0 on message from machine %d type %d "
		  "len %d, total len %d\n", message->machine_id, message->type, 
		  message->len, UTIL_Message_Size(message));
	  return 0;
      }
  }

  /* This is a signed message */
  /*
  if (!VAL_Validate_Signed_Message(message, num_bytes, 1)) {
    Alarm(VALID_PRINT, "Validate signed message failed.\n");
    VALIDATE_FAILURE_LOG(message,num_bytes);
    return 0;
  }
  */

  switch (message->type) {

  case UPDATE:
    if((!VAL_Validate_Update((update_message *)(content), num_content_bytes))){
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_REQUEST:
    if((!VAL_Validate_PO_Request((po_request_message *)content,
				 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PO_ACK:
    if((!VAL_Validate_PO_Ack((po_ack_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_ARU:
    if((!VAL_Validate_PO_ARU((po_aru_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PROOF_MATRIX:
    if((!VAL_Validate_Proof_Matrix((proof_matrix_message *)content,
				   num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PRE_PREPARE:
    if((!VAL_Validate_Pre_Prepare((pre_prepare_message *)content,
				  num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PREPARE:
    if((!VAL_Validate_Prepare((prepare_message *)content,
			      num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case COMMIT:
    if((!VAL_Validate_Commit((commit_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_PING:
    if((!VAL_Validate_RTT_Ping((rtt_ping_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_PONG:
    if((!VAL_Validate_RTT_Pong((rtt_pong_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case RTT_MEASURE:
    if((!VAL_Validate_RTT_Measure((rtt_measure_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case TAT_MEASURE:
    if((!VAL_Validate_TAT_Measure((tat_measure_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case TAT_UB:
    if((!VAL_Validate_TAT_UB((tat_upper_bound_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;    

  case NEW_LEADER:
    if((!VAL_Validate_New_Leader((new_leader_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case NEW_LEADER_PROOF:
    if((!VAL_Validate_New_Leader_Proof((new_leader_proof_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_INIT:
    if((!VAL_Validate_RB_Init((signed_message*)content,num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
    return 0;
    }
    break;

  case RB_ECHO:
    if((!VAL_Validate_RB_Echo((signed_message*)content,num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_READY:
    if((!VAL_Validate_RB_Ready((signed_message*)content,num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case REPORT:
    if(!VAL_Validate_Report((report_message*)content, num_content_bytes)) {
	return 0;
    }
    break;

  case PC_SET:
    if (!VAL_Validate_PC_Set((pc_set_message*)content, num_content_bytes)) {
	return 0;
    }
    break;

  case VC_LIST:
    if((!VAL_Validate_VC_List((vc_list_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case VC_PARTIAL_SIG:
    if((!VAL_Validate_VC_Partial_Sig((vc_partial_sig_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case VC_PROOF:
    if((!VAL_Validate_VC_Proof((vc_proof_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case REPLAY:
    if((!VAL_Validate_Replay((replay_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break; 

  case REPLAY_PREPARE:
    if((!VAL_Validate_Replay_Prepare((replay_prepare_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break; 

  case REPLAY_COMMIT:
    if((!VAL_Validate_Replay_Commit((replay_commit_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break; 

  case ORD_CERT:
    if((!VAL_Validate_ORD_Cert((ord_cert_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  case ORD_CERT_REPLY:
    if((!VAL_Validate_Retrieved_ORD_Cert((ord_cert_reply_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_CERT:
    if((!VAL_Validate_PO_Cert((po_cert_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  case PO_CERT_REPLY:
    if((!VAL_Validate_Retrieved_PO_Cert((po_cert_reply_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case DB_STATE_DIGEST_REQUEST:
    if((!VAL_Validate_DB_Digest_Request((db_state_digest_request_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
     break;
          
  case DB_STATE_DIGEST_REPLY:
    if((!VAL_Validate_DB_Digest_Reply((db_state_digest_reply_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
     break;
          
  case DB_STATE_VALIDATION_REQUEST:
    if((!VAL_Validate_DB_Val_Request((db_state_validation_request_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  case DB_STATE_VALIDATION_REPLY:
    if((!VAL_Validate_DB_Val_Reply((db_state_validation_reply_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  case DB_STATE_TRANSFER_REQUEST:
    if((!VAL_Validate_DB_State_Tran_Request((db_state_transfer_request_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  case DB_STATE_TRANSFER_REPLY:
    // The validation of DB_STATE_TRANSFER_REPLY messages is done during proactive recovery
    break;

  case CATCH_UP:
    if((!VAL_Validate_Catch_Up((catch_up_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  case CATCH_UP_REPLY:
    if((!VAL_Validate_Catch_Up_Reply((catch_up_reply_message *)content, num_content_bytes))) {
        VALIDATE_FAILURE_LOG(message, num_bytes);
        return 0;
    }
    break;

  default:
    Alarm(PRINT, "Not yet checking message type %d!\n", message->type);
  }

  return 1;
}

/* Determine if a signed message is valid. */
int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature) 
{
  int32u sig_type;
  int32u sender_id;

  if (num_bytes < (sizeof(signed_message))) {
    VALIDATE_FAILURE("Num bytes < sizeof(signed_message)");
    return 0;
  }
   
  if (num_bytes != mess->len + sizeof(signed_message) + 
      MT_Digests_(mess->mt_num) * DIGEST_SIZE) {
    Alarm(PRINT, "num_bytes = %d, signed_message = %d, mess->len = %d, "
	  "digests = %d\n",
	  num_bytes, sizeof(signed_message), mess->len, 
	  MT_Digests_(mess->mt_num));
    VALIDATE_FAILURE("num_bytes != mess->len + sizeof(signed_message)");
    return 0;
  }

  sig_type = VAL_Signature_Type( mess->type );

  if (sig_type == VAL_TYPE_INVALID) {
    VALIDATE_FAILURE("Sig Type invalid");
    return 0;
  }

  /* TODO: Should probably check the sender */
  if(sig_type == VAL_SIG_TYPE_UNSIGNED)
    return 1;

  if (sig_type == VAL_SIG_TYPE_SERVER ||
      sig_type == VAL_SIG_TYPE_CLIENT) {
    sender_id = mess->machine_id;
  } else {
    /* threshold signed */
    sender_id = mess->site_id;
  }
  
  if (!VAL_Validate_Sender(sig_type, sender_id)) {
    VALIDATE_FAILURE("Invalid sender");
    return 0;
  }
  
  if (!VAL_Is_Valid_Signature(sig_type, sender_id, mess->site_id, mess)) {
    VALIDATE_FAILURE("Invalid signature");
    return 0;
  }
    
  return 1; /* Passed all checks */
}

/* Determine if the message type is valid and if so return which type of
 * signature is on the message, a client signature, a server signature, or a
 * threshold signature. 
 * 
 * returns: VAL_SIG_TYPE_SERVER, VAL_SIG_TYPE_CLIENT, VAL_SIG_TYPE_SITE, or
 * VAL_TYPE_INVALID */
int32u VAL_Signature_Type(int32u message_type) 
{
  int sig_type = VAL_TYPE_INVALID;
  
  /* Return the type of the signature based on the type of the message. If
   * the type is not found, then return TYPE_INVALID */

  switch(message_type) {

  case UPDATE:
    sig_type = VAL_SIG_TYPE_CLIENT;
    break;
  
  case PO_REQUEST:
  case PO_ACK:
  case PO_ARU:
  case PROOF_MATRIX:
  case RECON:
  case PRE_PREPARE:
  case PREPARE:
  case COMMIT:
  case RTT_PING:
  case RTT_PONG:
  case RTT_MEASURE:
  case TAT_MEASURE:
  case TAT_UB: 
  case NEW_LEADER: 
  case NEW_LEADER_PROOF:
  case RB_INIT:
  case RB_ECHO:
  case RB_READY:
  case REPORT:
  case PC_SET:
  case VC_LIST:
  case VC_PARTIAL_SIG:
  case REPLAY_PREPARE:
  case REPLAY_COMMIT:
  case VC_PROOF:
  case REPLAY:
  case PO_CERT:
  case PO_CERT_REPLY:
  case ORD_CERT:
  case ORD_CERT_REPLY:
  case DB_STATE_DIGEST_REQUEST:
  case DB_STATE_DIGEST_REPLY:
  case DB_STATE_VALIDATION_REQUEST:
  case DB_STATE_VALIDATION_REPLY:
  case DB_STATE_TRANSFER_REQUEST:
  case DB_STATE_TRANSFER_REPLY:
  case CATCH_UP:
  case CATCH_UP_REPLY:
    sig_type = VAL_SIG_TYPE_SERVER;
    break;
  }

  return sig_type;
} 

/* Determine if the sender is valid depending on the specified signature type.
 * 
 * return: 1 if sender is valid, 0 if sender is not valid */
int32u VAL_Validate_Sender(int32u sig_type, int32u sender_id) 
{
  if (sender_id < 1) 
    return 0;

  if (sig_type == VAL_SIG_TYPE_SERVER && sender_id <= NUM_SERVERS) {
    return 1;
  } 
    
  if (sig_type == VAL_SIG_TYPE_CLIENT &&
      sender_id <= NUM_CLIENTS) {
    return 1;
  }	

  return 0;
}

/* Determine if the signature is valid. Assume that the lengths of the message
 * is okay. */
int32u VAL_Is_Valid_Signature(int32u sig_type, int32u sender_id, 
			      int32u site_id, signed_message *mess) 
{
  int32 ret;
  
  if (sig_type == VAL_SIG_TYPE_SERVER) {
    /* Check an RSA signature using openssl. A server sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
			 ((byte*)mess) + SIGNATURE_SIZE,
			 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
			 (byte*)mess, 
			 sender_id,
			 RSA_SERVER
			 );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Server Failed %d %d\n",
	    mess->type, mess->machine_id);
    return ret; 
  }
   
  if (sig_type == VAL_SIG_TYPE_CLIENT) {
    /* Check an RSA signature using openssl. A client sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
			 ((byte*)mess) + SIGNATURE_SIZE,
			 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
			 (byte*)mess, 
			 sender_id,
			 RSA_CLIENT
			 );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Client Failed %d\n", mess->type);
    return ret; 
  }
  
  return 0;
}

/* Determine if an update is valid */
int32u VAL_Validate_Update(update_message *update, int32u num_bytes) 
{
  
  /* Check to determine if the update is valid. We have already checked to
   * see if the signature verified. We only need to make sure that the packet
   * is large enough for the timestamp. */
  
  if (num_bytes < (sizeof(update_message))) {
    VALIDATE_FAILURE("");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_PO_Request(po_request_message *po_request, int32u num_bytes)
{
  signed_message *mess;
  char *p;
  int32u i;
  int32u wa_bytes;


  if (num_bytes < (sizeof(po_request_message))) {
    VALIDATE_FAILURE("Local PO-Request bad size");
    return 0;
  }
  
  /* This is the start of the events contained in the PO-Request */
  p = (char *)(po_request + 1);

  for(i = 0; i < po_request->num_events; i++) {
    mess = (signed_message *)p;
    wa_bytes = 0;

    if(!VAL_Validate_Message(mess, 
			     mess->len + sizeof(signed_message) + wa_bytes)) {
      Alarm(PRINT, "Event %d of %d PO-Request invalid\n", i, po_request->num_events);
      VALIDATE_FAILURE("PO-Request event invalid");
      return 0;
    }
    else {
      p += mess->len + sizeof(signed_message) + wa_bytes;
    }
  }
  
  return 1;
} 

int32u VAL_Validate_PO_Ack(po_ack_message *po_ack, int32u num_bytes)
{
  int32u expected_num_bytes;

  if(num_bytes < sizeof(po_ack_message)) {
    VALIDATE_FAILURE("PO-Ack wrong size");
    return 0;
  }

  expected_num_bytes = (sizeof(po_ack_message) +
			(po_ack->num_ack_parts * sizeof (po_ack_part)));

  if(num_bytes != expected_num_bytes) {
    VALIDATE_FAILURE("PO-Ack wrong expected bytes");
    return 0;
  }

  int i;
  po_ack_part *part = (po_ack_part*)(po_ack+1);
  for (i = 0; i < po_ack->num_ack_parts; ++i) {
      if (part->seq_num <= 0) {
	VALIDATE_FAILURE("PO-Ack part incorrect seq_num");
	return 0;
      }
      if (part->originator == 0 || part->originator > NUM_SERVERS) {
	VALIDATE_FAILURE("PO-Ack part incorrect originator");
	return 0;
      }
    
  }
  
  return 1;
}

int32u VAL_Validate_PO_ARU(po_aru_message *po_aru, int32u num_bytes)
{
  if (num_bytes != (sizeof(po_aru_message))) {
    VALIDATE_FAILURE("PO_ARU bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Proof_Matrix(proof_matrix_message *pm, int32u num_bytes)
{

  if(num_bytes < sizeof(proof_matrix_message) || num_bytes != sizeof(proof_matrix_message) + sizeof(po_aru_signed_message) * pm->num_acks_in_this_message) {
    VALIDATE_FAILURE("proof_matrix wrong size");
    return 0;
  }

  int i;
  po_aru_signed_message *cur = (po_aru_signed_message*)(pm + 1);
  for (i = 0; i < pm->num_acks_in_this_message; i++) {
     if (cur->header.type == PO_ARU && !VAL_Validate_Message((signed_message*)cur, sizeof(po_aru_signed_message))) {
	//Alarm(PRINT, "sig: %c%c%c%c\n", cur->header.sig[0], cur->header.sig[1], cur->header.sig[2], cur->header.sig[3]);
	VALIDATE_FAILURE("Proof_Matrix: bad po-aru");
	return 0;
     }
     cur++;
  }
  
  return 1;
}

int32u VAL_Validate_Pre_Prepare(pre_prepare_message *pp, int32u num_bytes)
{
  Alarm(DEBUG, "VAL_Validate_Pre_Prepare\n");
  
  if(num_bytes < sizeof(pre_prepare_message) || num_bytes != sizeof(pre_prepare_message) + (sizeof(po_aru_signed_message) * pp->num_acks_in_this_message)) {
    VALIDATE_FAILURE("Pre-Prepare bad size");
    return 0;
  }

  if(pp->seq_num < 1) {
    Alarm(PRINT, "seq_num %d\n", pp->seq_num);
    VALIDATE_FAILURE("Pre-Prepare bad seq");
    return 0;
  }

  int32u total_parts;
  /* TODO: MAKE THIS GENERIC FOR ANY f */
  if(NUM_FAULTS == 1)
    total_parts = 1;
  else
    total_parts = 2;

  if (pp->total_parts != total_parts) {
    VALIDATE_FAILURE("Pre-Prepare: bad total parts");
    return 0;
  }

  if (pp->part_num < 1 || pp->part_num > pp->total_parts) {
    VALIDATE_FAILURE("Pre-Prepare: bad part number");
    return 0;
  }

  int i;
  po_aru_signed_message *cur = (po_aru_signed_message*)(pp + 1);
  for (i = 0; i < pp->num_acks_in_this_message; i++) {
     if (cur->header.type == PO_ARU && !VAL_Validate_Message((signed_message*)cur, sizeof(po_aru_signed_message))) {
	//Alarm(PRINT, "sig: %c%c%c%c\n", cur->header.sig[0], cur->header.sig[1], cur->header.sig[2], cur->header.sig[3]);
	VALIDATE_FAILURE("Pre-Prepare: bad po-aru");
	 return 0;
     }
     cur++;
  }
  return 1;
}

int32u VAL_Validate_Prepare(prepare_message *prepare, int32u num_bytes)
{
  if(num_bytes != sizeof(prepare_message)) {
    VALIDATE_FAILURE("Prepare: bad size");
    return 0;
  }
  
  if(prepare->seq_num < 1) {
    VALIDATE_FAILURE("Prepare: bad seq");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Commit(commit_message *commit, int32u num_bytes)
{
  if(num_bytes != sizeof(commit_message)) {
    VALIDATE_FAILURE("Commit: bad size");
    return 0;
  }

  if(commit->seq_num < 1) {
    VALIDATE_FAILURE("Commit: Bad seq");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_RTT_Ping(rtt_ping_message *ping, int32u num_bytes)
{
    if(num_bytes != sizeof(rtt_ping_message)) {
	VALIDATE_FAILURE("RTT_Ping: bad size");
	return 0;
    }

    if (DATA.View != ping->view) {
	VALIDATE_FAILURE("RTT_Ping: incorrect view");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_RTT_Pong(rtt_pong_message *pong, int32u num_bytes)
{
    if(num_bytes != sizeof(rtt_pong_message)) {
	VALIDATE_FAILURE("RTT_Pong: bad size");
	return 0;
    }

    if (DATA.View != pong->view) {
	VALIDATE_FAILURE("RTT_Pong: incorrect view");
	return 0;
    }

    if (pong->ping_seq_num != DATA.SUS.ping_seq_num) {
	//printf("Got bad Pong from %d, seq # %d\n", mess->machine_id, pong->ping_seq_num);
	VALIDATE_FAILURE("RTT_Pong: bad seq_num");
	return 0;
    }

    if (pong->recipient != VAR.My_Server_ID) {
	VALIDATE_FAILURE("RTT_Pong: was not intended for me");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_RTT_Measure(rtt_measure_message *measure, int32u num_bytes)
{
    if(num_bytes != sizeof(rtt_measure_message)) {
	VALIDATE_FAILURE("RTT_Measure: bad size");
	return 0;
    }

    if (DATA.View != measure->view) {
	VALIDATE_FAILURE("RTT_Measure: incorrect view");
	return 0;
    }

    if (measure->recipient != VAR.My_Server_ID) {
	VALIDATE_FAILURE("RTT_Measure: was not intended for me");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_TAT_Measure(tat_measure_message *measure, int32u num_bytes)
{
    if(num_bytes != sizeof(tat_measure_message)) {
	VALIDATE_FAILURE("TAT_Measure: bad size");
	return 0;
    }

    if (DATA.View != measure->view) {
	VALIDATE_FAILURE("TAT_Measure: incorrect view");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_TAT_UB(tat_upper_bound_message *measure, int32u num_bytes)
{
    if(num_bytes != sizeof(tat_upper_bound_message)) {
	VALIDATE_FAILURE("TAT_UB: bad size");
	return 0;
    }

    if (DATA.View != measure->view) {
	VALIDATE_FAILURE("TAT_UB: incorrect view");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_New_Leader(new_leader_message *new_leader, int32u num_bytes)
{
    if(num_bytes != sizeof(new_leader_message)) {
	VALIDATE_FAILURE("New_Leader: bad size");
	return 0;
    }

    if (new_leader->new_view < DATA.View) {
	VALIDATE_FAILURE("New_Leader: incorrect view");
	return 0;
    }

    return 1;
}


int32u VAL_Validate_New_Leader_Proof(new_leader_proof_message *new_leader_proof, int32u num_bytes)
{
    if(num_bytes < sizeof(new_leader_proof_message)) {
	VALIDATE_FAILURE("New_Leader_Proof: bad size");
	return 0;
    }

    if (new_leader_proof->new_view < DATA.View) {
	VALIDATE_FAILURE("New_Leader_Proof: incorrect view");
	return 0;
    }

    signed_message *mess = (signed_message*)(new_leader_proof+1);
    int count = 0;
    int32u len = sizeof(new_leader_proof_message);

    while (count < 2*VAR.Faults+1 && len < num_bytes) {
	int32u size = UTIL_Message_Size(mess);
	if (mess->type != NEW_LEADER) {
	    VALIDATE_FAILURE("New_Leader_Proof: Message not New_Leader");
	    return 0;
	}
	if (size > num_bytes - len) {
	    VALIDATE_FAILURE("New_Leader_Proof: bad New Leader size");
	    return 0;
	}
	if (!VAL_Validate_Message(mess, size)) {
	    return 0;
	}
	new_leader_message *new_leader = (new_leader_message*)(mess+1);
	if (new_leader->new_view == new_leader_proof->new_view) {
	    count++;
	} else {
	    VALIDATE_FAILURE("New_Leader_Proof: mismatch on views");
	    Alarm(PRINT, "mismatch on views %d %d\n", new_leader->new_view, new_leader_proof->new_view);
	    return 0;
	}
	len += size;
	mess = (signed_message*)((char*)mess + size);
    }
    if (len != num_bytes) {
	VALIDATE_FAILURE("New_Leader_Proof: bad total size");
	return 0;
    }

    if (count < 2*VAR.Faults+1) {
	VALIDATE_FAILURE("New_Leader_Proof: incorrect number of messages");
	Alarm(PRINT, "View %d Only %d\n", new_leader_proof->new_view, count);
	return 0;	
    }

    return 1;
}

int32u VAL_Validate_RB_Init(signed_message *payload, int32u num_bytes)
{
    if(num_bytes <= sizeof(signed_message) + sizeof(reliable_broadcast_tag)) {
	VALIDATE_FAILURE("RB_Init: bad size");
	return 0;
    }
    
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(payload+1);
    if (DATA.View != rb_tag->view) {
	VALIDATE_FAILURE("RB_Init: incorrect view");
	return 0;
    }

    if (!VAL_Validate_Message(payload, num_bytes)) {
	VALIDATE_FAILURE("RB_Init: invalid payload message");
	return 0;
    }

    //this should really be done in validation, otherwise might deliver things ahead of time
    if (DATA.REL.seq_num[payload->machine_id] > rb_tag->seq_num) {
	VALIDATE_FAILURE("RB_Init: incorrect seq_num");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_RB_Echo(signed_message *payload, int32u num_bytes)
{
    if(num_bytes <= sizeof(signed_message) + sizeof(reliable_broadcast_tag)) {
	VALIDATE_FAILURE("RB_Echo: bad size");
	return 0;
    }

    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(payload+1);
    if (DATA.View != rb_tag->view) {
	VALIDATE_FAILURE("RB_Echo: incorrect view");
	return 0;
    }

    if (!VAL_Validate_Message(payload, num_bytes)) {
	VALIDATE_FAILURE("RB_Echo: invalid payload message");
	return 0;
    }

    if (DATA.REL.seq_num[payload->machine_id] > rb_tag->seq_num) {
	VALIDATE_FAILURE("RB_Echo: incorrect seq_num");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_RB_Ready(signed_message *payload, int32u num_bytes)
{
    if(num_bytes <= sizeof(signed_message) + sizeof(reliable_broadcast_tag)) {
	VALIDATE_FAILURE("RB_Ready: bad size");
	return 0;
    }

    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(payload+1);
    if (DATA.View != rb_tag->view) {
	VALIDATE_FAILURE("RB_Ready: incorrect view");
	return 0;
    }

    if (!VAL_Validate_Message(payload, num_bytes)) {
	VALIDATE_FAILURE("RB_Ready: invalid payload message");
	return 0;
    }

    if (DATA.REL.seq_num[payload->machine_id] > rb_tag->seq_num) {
	VALIDATE_FAILURE("RB_Ready: incorrect seq_num");
	return 0;
    }
    return 1;
}

int32u VAL_Validate_Report(report_message *report, int32u num_bytes) {
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(report);
    if(num_bytes != sizeof(report_message)) {
	VALIDATE_FAILURE("Report: bad size");
	return 0;
    }

    if (rb_tag->view != DATA.View) {
	VALIDATE_FAILURE("Report: incorrect view");
	return 0;
    }

    if (rb_tag->seq_num != 0) {
	VALIDATE_FAILURE("Report: seq_num != 0");
	return 0;
    }

    if (rb_tag->machine_id == 0 || rb_tag->machine_id > NUM_SERVERS) {
	VALIDATE_FAILURE("Report: Incorrect machine_id");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_PC_Set(pc_set_message *pc_set,   int32u num_bytes) {
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(pc_set);
    if(num_bytes < sizeof(pc_set_message)) {
	VALIDATE_FAILURE("PC_Set: bad size");
	return 0;
    }

    if (rb_tag->view != DATA.View) {
	VALIDATE_FAILURE("PC_Set: incorrect view");
	return 0;
    }

    if (rb_tag->machine_id == 0 || rb_tag->machine_id > NUM_SERVERS) {
	VALIDATE_FAILURE("PC_Set: Incorrect machine_id");
	return 0;
    }

    if (rb_tag->seq_num < 1 || rb_tag->seq_num > DATA.VIEW.report[rb_tag->machine_id].pc_set_size) {
	VALIDATE_FAILURE("PC_Set: seq_num out of bounds");
	Alarm(DEBUG, "id %d seq_num %d pc_set_size %d\n", rb_tag->machine_id, rb_tag->seq_num, DATA.VIEW.report[rb_tag->machine_id].pc_set_size);
	return 0;
    }

    pre_prepare_message *pre_prepare; 
    prepare_message *prepare;
    signed_message *mess;
    mess = (signed_message*)(pc_set+1);
    int count = 0;
    int32u len = sizeof(pc_set_message);
    if (mess->type != PRE_PREPARE) {
	VALIDATE_FAILURE("PC_Set: Message not a Pre-Prepare");
	return 0;
    }
    int32u size = UTIL_Message_Size(mess);
    if (size > num_bytes-len) {
	VALIDATE_FAILURE("PC_SET: bad PrePrepare size");
    }
   
    if (!VAL_Validate_Message(mess, size)) {
	VALIDATE_FAILURE("PC_Set: Prepare failed");
	return 0;
    }
    pre_prepare = (pre_prepare_message*)(mess+1);
    len += size;
    mess = (signed_message*)((char*)mess + size);

    while (count < 2*VAR.Faults && len < num_bytes) {
	size = UTIL_Message_Size(mess);
	//Alarm(PRINT, "Verifying Prepares in PC_Set\n");
	if (mess->type != PREPARE) {
	    //Alarm(PRINT, "continue... %d\n", mess->type);
	    VALIDATE_FAILURE("PC_Set: Message not a Prepare");
	    return 0;
	}
	if (size > num_bytes - len) {
	    VALIDATE_FAILURE("PC_Set: bad Prepare size");
	    return 0;
	}
	if (!VAL_Validate_Message(mess, size)) {
	    VALIDATE_FAILURE("PC_Set: Prepare failed");
	    return 0;
	}
	prepare = (prepare_message*)(mess+1);
	if (pre_prepare->seq_num != prepare->seq_num) {
	    VALIDATE_FAILURE("PC_Set: Prepare doesn't match pre-prepare");
	    return 0;
	}
	len += size;
	mess = (signed_message*)((char*)mess + size);
	count++;
    }

    if (len != num_bytes) {
	VALIDATE_FAILURE("PC_Set: bad total size");
	return 0;
    }

    if (count < 2*VAR.Faults) {
	VALIDATE_FAILURE("PC_Set: incorrect number of messages");
	Alarm(PRINT, "Only %d\n", count);
	return 0;	
    }

    return 1;
}

int32u VAL_Validate_VC_List(vc_list_message *vc_list, int32u num_bytes) {
    if(num_bytes != sizeof(vc_list_message)) {
	VALIDATE_FAILURE("VC List: bad size");
	return 0;
    }

    if (vc_list->view != DATA.View) {
	VALIDATE_FAILURE("VC List: incorrect view");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_VC_Partial_Sig (vc_partial_sig_message *vc_partial_sig, int32u num_bytes){
    if(num_bytes != sizeof(vc_partial_sig_message)) {
	VALIDATE_FAILURE("VC Partial Sig: bad size");
	return 0;
    }

    if (vc_partial_sig->view != DATA.View) {
	VALIDATE_FAILURE("VC Partial Sig: incorrect view");
	return 0;
    }
    return 1;
}

int32u VAL_Validate_VC_Proof (vc_proof_message *vc_proof, int32u num_bytes){
    if(num_bytes != sizeof(vc_proof_message)) {
	VALIDATE_FAILURE("VC Proof: bad size");
	return 0;
    }

    if (vc_proof->view != DATA.View) {
	VALIDATE_FAILURE("VC Proof: incorrect view");
	return 0;
    }

    byte digest[DIGEST_SIZE];
    OPENSSL_RSA_Make_Digest( 
	  vc_proof, 
	  3*sizeof(int32u), 
	  digest );

    if (!TC_Verify_Signature(1, vc_proof->thresh_sig, digest)) {
	VALIDATE_FAILURE("VC Proof: invalid threshold signature");
	return 0;
    }

    return 1;
}

int32u VAL_Validate_Replay(replay_message *replay, int32u num_bytes) {

    return VAL_Validate_VC_Proof((vc_proof_message*)replay, num_bytes);
}

int32u VAL_Validate_Replay_Prepare(replay_prepare_message *replay, int32u num_bytes) {

    return 1;
}

int32u VAL_Validate_Replay_Commit(replay_commit_message *replay, int32u num_bytes) {

    return 1;
}

/* Validate messages for proactive recovery */

int32u VAL_Validate_ORD_Cert(ord_cert_message *ord_cert, int32u num_bytes) {
    if(num_bytes != sizeof(ord_cert_message)) {
        Alarm(PRINT, "ord_cert_message %d %d\n", num_bytes, sizeof(ord_cert_message));
        VALIDATE_FAILURE("ORD_CERT: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_Retrieved_ORD_Cert(ord_cert_reply_message *cert_reply, int32u num_bytes) {
  if(num_bytes < sizeof(ord_cert_reply_message)) {
    Alarm(PRINT, "ord_cert_reply_message_size %d %d\n", num_bytes, sizeof(ord_cert_reply_message));
    VALIDATE_FAILURE("ORD_CERT_REPLY: bad size");
    return 0;
  }
#if 0
  /* Message validation occurs during recovery */
  signed_message *mess;
  complete_pre_prepare_message pre_prepare;
  prepare_message *prepare;
  commit_message *commit;
  int32u count = 0, len, size = 0;
  mess = (signed_message *)(cert_reply + 1);
  len = sizeof(ord_cert_reply_message);

  pre_prepare = cert_reply->pre_prepare;
  len += size;

  while(count < 2 * VAR.Faults && len < num_bytes) {
    size = UTIL_Message_Size(mess);
    if(mess->type != PREPARE) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: Message not a PREPARE");
      return 0;
    }
    if(size > num_bytes - len) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: bad PREPARE size");
      return 0;
    }
    if(!VAL_Validate_Message(mess, size)) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: PREPARE failed");
      return 0;
    }
    prepare = (prepare_message *)(mess + 1);
    if(prepare->seq_num != pre_prepare.seq_num) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: PREPARE doesn't match PRE_PREPARE");
      return 0;
    }
    len += size;
    mess = (signed_message*)((char*)mess + size);
    count++;
  } 

  count = 0;
  while(count < 2 * VAR.Faults + 1 && len < num_bytes) {
    size = UTIL_Message_Size(mess);
    if(mess->type != COMMIT) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: Message not a COMMIT");
      return 0;
    }
    if(size > num_bytes - len) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: bad COMMIT size");
      return 0;
    }
    if(!VAL_Validate_Message(mess, size)) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: COMMIT failed");
      return 0;
    }
    commit = (commit_message *)(mess + 1);
    if(commit->seq_num != pre_prepare.seq_num) {
      VALIDATE_FAILURE("ORD_CERT_REPLY: COMMIT doesn't match PRE_PREPARE");
      return 0;
    }
    len += size;
    mess = (signed_message*)((char*)mess + size);
    count++;
  }

  if(len != num_bytes) {
    VALIDATE_FAILURE("ORD_CERT_REPLY: bad total size");
    return 0;
  }

  if(count < 2 * VAR.Faults) {
    VALIDATE_FAILURE("ORD_CERT_REPLY: incorrect number of messages");
    Alarm(PRINT, "Only %d\n", count);
    return 0;
  }
#endif
  return 1;
}

int32u VAL_Validate_PO_Cert(po_cert_message *po_cert, int32u num_bytes) {
    if(num_bytes != sizeof(po_cert_message)) {
        Alarm(PRINT, "po_cert_message %d %d\n", num_bytes, sizeof(po_cert_message));
        VALIDATE_FAILURE("PO_CERT: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_Retrieved_PO_Cert(po_cert_reply_message *cert_reply, int32u num_bytes) {
  if(num_bytes < sizeof(po_cert_reply_message)) {
    Alarm(PRINT, "po_cert_reply_message_size %d %d\n", num_bytes, sizeof(po_cert_reply_message));
    VALIDATE_FAILURE("PO_CERT_REPLY: bad size");
    return 0;
  }
#if 0
  /* Message validation occurs during recovery */
  signed_message *mess;
  int32u size, len;
  mess = (signed_message *)(cert_reply + 1);
  len = sizeof(po_cert_reply_message);
  size = UTIL_Message_Size(mess);
  
  if(mess->type != PO_REQUEST) {
    Alarm(PRINT, "po_cert_reply_message po_request type %d\n", mess->type);
    VALIDATE_FAILURE("PO_CERT_REPLY: Message not a PO_REQUEST");
    return 0;
  }

  if(size > num_bytes - len)
    VALIDATE_FAILURE("PO_CERT_REPLY: bad PO_REQUEST size");

  if(!VAL_Validate_Message(mess, size)) {
    VALIDATE_FAILURE("PO_CERT_REPLY: PO_REQUEST failed");
    return 0;
  }
#endif
  return 1;
}

int32u VAL_Validate_DB_Digest_Request(db_state_digest_request_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(db_state_digest_request_message)) {
        Alarm(PRINT, "db_state_digest_request_message %d %d\n", num_bytes, sizeof(db_state_digest_request_message));
        VALIDATE_FAILURE("DB_STATE_DIGEST_REQUEST_MESSAGE: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_DB_Digest_Reply(db_state_digest_reply_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(db_state_digest_reply_message)) {
        Alarm(PRINT, "db_state_digest_reply_message %d %d\n", num_bytes, sizeof(db_state_digest_reply_message));
        VALIDATE_FAILURE("DB_STATE_DIGEST_REPLY_MESSAGE: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_DB_Val_Request(db_state_validation_request_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(db_state_validation_request_message)) {
        Alarm(PRINT, "db_state_validation_request_message %d %d\n", num_bytes, sizeof(db_state_validation_request_message));
        VALIDATE_FAILURE("DB_STATE_VALIDATION_REQUEST_MESSAGE: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_DB_Val_Reply(db_state_validation_reply_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(db_state_validation_reply_message)) {
        Alarm(PRINT, "db_state_validation_reply_message %d %d\n", num_bytes, sizeof(db_state_validation_reply_message));
        VALIDATE_FAILURE("DB_STATE_VALIDATION_REPLY_MESSAGE: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_DB_State_Tran_Request(db_state_transfer_request_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(db_state_transfer_request_message)) {
        Alarm(PRINT, "db_state_transfer_request_message %d %d\n", num_bytes, sizeof(db_state_transfer_request_message));
        VALIDATE_FAILURE("DB_STATE_TRANSFER_REQUEST_MESSAGE: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_Catch_Up(catch_up_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(catch_up_message)) {
        Alarm(PRINT, "catch_up_message %d %d\n", num_bytes, sizeof(catch_up_message));
        VALIDATE_FAILURE("CATCH_UP_MESSAGE: bad size");
        return 0;
    }
    return 1;
}

int32u VAL_Validate_Catch_Up_Reply(catch_up_reply_message *mess, int32u num_bytes) {
    if(num_bytes != sizeof(catch_up_reply_message)) {
        Alarm(PRINT, "catch_up_reply_message %d %d\n", num_bytes, sizeof(catch_up_reply_message));
        VALIDATE_FAILURE("CATCH_UP_REPLY_MESSAGE: bad size");
        return 0;
    }
    return 1;
}
