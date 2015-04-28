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
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *
 * Copyright (c) 2008 - 2014
 * The Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Prime research was provided by the Defense Advanced
 * Research Projects Agency (DARPA) and The National Security Agency (NSA).
 * Prime is not necessarily endorsed by DARPA or the NSA.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <time.h>
#include "spu_alarm.h"
#include "spu_memory.h"
#include "order.h"
#include "data_structs.h"
#include "utility.h"
#include "def.h"
#include "apply.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "dispatcher.h"
#include "signature.h"
#include "objects.h"
#include "proactive_recovery.h"
#include "stdutil/stdhash.h"
#include "merkle.h"
#include "packets.h"
#include "data_structs.h"

/* Global variables */
#define STATE_TRANSFER_SEC  1
#define STATE_TRANSFER_USEC 0
#define DATA_BLOCK_USEC     1000000

/* Support Large File Use */
#define _LARGEFILE_SOURCE   1
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS   64

/* External variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Data structures that contain (key,value) mappings */
stdhash Retrieved_PO_Cert[NUM_SERVER_SLOTS];
stdhash Retrieved_ORD_Cert;
stdhash DB_RECOVERY_State_Transfer[NUM_SERVER_SLOTS];

/* Other variables */
stdit ORD_iterator;
stdit PO_iterator[NUM_SERVERS];
int32u PO_Index = 1;
int32u blacklist[NUM_SERVERS + 1];
FILE *output_state;
data_block *db_state_block;
util_stopwatch *block_transfer;

/* Local functions */
void RECOVERY_Send_Ckpt_Digest_Req_Periodically(int, void *);
void RECOVERY_Deliver_Ckpt_Digest_Req(signed_message *);
void RECOVERY_Send_Ckpt_Digest_Reply(int32u);
void RECOVERY_Deliver_Ckpt_Digest_Reply(signed_message *);
void RECOVERY_State_Transfer(void);
void RECOVERY_Retrieve_Single_Block(int32u);
void RECOVERY_Send_DB_State_Val_Request(int32u, int32u, int32u);
void RECOVERY_Deliver_DB_State_Val_Request(signed_message *);
void RECOVERY_Send_DB_State_Val_Reply(int32u, int32u, int32u);
void RECOVERY_Deliver_DB_State_Val_Reply(signed_message *);
void RECOVERY_Validate_Block_Digest(int32u);
void RECOVERY_Send_DB_State_Tran_Request(int32u, int32u, int32u);
void RECOVERY_Deliver_DB_State_Tran_Request(signed_message *);
void RECOVERY_Send_DB_State_Tran_Reply(int32u, int32u, int32u);
void RECOVERY_Deliver_DB_State_Tran_Reply(signed_message *);
void RECOVERY_Check_ST_Periodically(int, void *);
void RECOVERY_Write_On_Disk(int32u);
void RECOVERY_Print_Digest(byte *);
void RECOVERY_Deliver_Catch_Up(signed_message *);
void RECOVERY_Send_Catch_Up_Reply(int32u);
void RECOVERY_Deliver_Catch_Up_Reply(signed_message *);
void RECOVERY_Validate_Order_Messages(void);
void RECOVERY_Validate_PO_Messages(void);
void RECOVERY_Retrieve_ORD_Cert(int32u);
void RECOVERY_Send_ORD_Cert_Request(void);
void RECOVERY_Deliver_ORD_Cert_Request(signed_message *);
void RECOVERY_Deliver_ORD_Cert_Reply(signed_message *);
void RECOVERY_Verify_ORD_Cert(int32u);
void RECOVERY_Retrieve_PO_Cert(int32u, int32u);
void RECOVERY_Send_PO_Cert_Request(void);
void RECOVERY_Deliver_PO_Cert_Request(signed_message *);
void RECOVERY_Deliver_PO_Cert_Reply(signed_message *);
void RECOVERY_Execute_ORD_Cert(void);
int32u RECOVERY_Verify_PO_Cert(signed_message **);
int32u RECOVERY_Verify_Prepare_Cert(signed_message *, complete_pre_prepare_message *);
int32u RECOVERY_Verify_Commit_Cert(signed_message *, complete_pre_prepare_message *);
retrieved_cert *RECOVERY_Get_ORD_Cert(int32u);
retrieved_cert *RECOVERY_Get_ORD_Cert_If_Exists(int32u);
retrieved_cert *RECOVERY_Get_PO_Cert(int32u, int32u);
retrieved_cert *RECOVERY_Get_PO_Cert_If_Exists(int32u, int32u);
db_state_part  *RECOVERY_Get_DB_State_Part(int32u, int32u);
db_state_part  *RECOVERY_Get_DB_State_Part_If_Exists(int32u, int32u);
void RECOVERY_Cleanup();
void RECOVERY_Read_State();
int32u RECOVERY_Select_Server();

//-------------------------------/
//  PROACTIVE RECOVERY PROTOCOL  /
//-------------------------------/

void RECOVERY_Dispatcher(signed_message *mess) {
  switch (mess->type) {

  case ORD_CERT:
    RECOVERY_Deliver_ORD_Cert_Request(mess);
    break;
   
  case ORD_CERT_REPLY:
    RECOVERY_Deliver_ORD_Cert_Reply(mess);
    break;

  case PO_CERT:
    RECOVERY_Deliver_PO_Cert_Request(mess);
    break;

  case PO_CERT_REPLY:
    RECOVERY_Deliver_PO_Cert_Reply(mess);
    break;

  case DB_STATE_DIGEST_REQUEST:
    RECOVERY_Deliver_Ckpt_Digest_Req(mess);
    break;

  case DB_STATE_DIGEST_REPLY:
    RECOVERY_Deliver_Ckpt_Digest_Reply(mess);
    break;

  case DB_STATE_VALIDATION_REQUEST:
    RECOVERY_Deliver_DB_State_Val_Request(mess);
    break;

  case DB_STATE_VALIDATION_REPLY:
    RECOVERY_Deliver_DB_State_Val_Reply(mess);
    break;

  case DB_STATE_TRANSFER_REQUEST:
    RECOVERY_Deliver_DB_State_Tran_Request(mess);
    break;

  case DB_STATE_TRANSFER_REPLY:
    RECOVERY_Deliver_DB_State_Tran_Reply(mess);
    break;

  case CATCH_UP:
    RECOVERY_Deliver_Catch_Up(mess);
    break;

  case CATCH_UP_REPLY:
    RECOVERY_Deliver_Catch_Up_Reply(mess);
    break;

  default:
    INVALID_MESSAGE("PR Dispatcher");
  }
}

/*********************************
 * STATE VALIDATION AND TRANSFER *
 *********************************/

void RECOVERY_Initialize_Data_Structure() {

  srand(time(NULL));
  output_state = fopen("/tmp/db_state_output.sql", "w");
  if((DATA.STATE.fp = fopen("../state/1Gig.sql", "r")) == NULL) {
    Alarm(PRINT, "Could not open state file.\n");
    exit(0);
  }

  DATA.STATE.checkpoint_id         = 1;
  DATA.STATE.next_data_block       = 1;
  DATA.STATE.number_of_replies     = 0;
  DATA.STATE.state_ready           = 0;
  DATA.STATE.digest_ready          = 0;
  DATA.STATE.retrieved_data_blocks = 0;
  DATA.STATE.last_written_block    = 0;
  DATA.STATE.transferring          = 0;

  fseeko(DATA.STATE.fp, 0L, SEEK_END);
  DATA.STATE.state_size = ftello(DATA.STATE.fp);
  fseeko(DATA.STATE.fp, 0L, SEEK_SET);
  DATA.STATE.num_of_blocks = ceil((double)DATA.STATE.state_size/(BLOCK_SIZE));
  DATA.STATE.parts_per_data_block = ceil((double)(BLOCK_SIZE)/(PAYLOAD_SIZE));

  memset(blacklist, 0, sizeof(int32u) * (NUM_SERVERS + 1));
  RECOVERY_Read_State();

  RECOVERY_Initialize_Catch_Up_Struct();
  RECOVERY_Send_Ckpt_Digest_Req_Periodically(0, NULL);
}

void RECOVERY_Send_Ckpt_Digest_Req_Periodically(int dummy, void *dummyp) {
  signed_message *mess;
  int32u dest_bits = 0, i;
  sp_time t;

  if(DATA.STATE.state_ready == 1)
    return;

  // Send a request for the digest of the state at checkpoint number checkpoint_id
  for(i = 1; i <= NUM_SERVERS; i++)
    if(i != VAR.My_Server_ID)
      UTIL_Bitmap_Set(&dest_bits, i);
  mess = RECOVERY_Construct_DB_State_Digest_Request_Message(DATA.STATE.checkpoint_id);
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(DB_STATE_DIGEST_REQUEST));
  dec_ref_cnt(mess);
  Alarm(DEBUG, "Retrieving the digest of the database state...\n");

  t.sec  = 0;
  t.usec = 500000;
  E_queue(RECOVERY_Send_Ckpt_Digest_Req_Periodically, 0, NULL, t);
}

void RECOVERY_Deliver_Ckpt_Digest_Req(signed_message *mess) {
/*
  db_state_digest_request_message *db_digest;
  db_digest = (db_state_digest_request_message *)(mess + 1);
  DATA.STATE.checkpoint_id = db_digest->checkpoint_id;
*/
  RECOVERY_Send_Ckpt_Digest_Reply(mess->machine_id);
}

void RECOVERY_Send_Ckpt_Digest_Reply(int32u sender_id) {
  signed_message *mess;
  int32u dest_bits = 0;

  Alarm(DEBUG, "Computing the digest of checkpoint %d ...\n", DATA.STATE.checkpoint_id);

  UTIL_Bitmap_Set(&dest_bits, sender_id);
  mess = RECOVERY_Construct_DB_State_Digest_Reply_Message(DATA.STATE.checkpoint_id, DATA.STATE.digest, DATA.STATE.state_size);
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(DB_STATE_DIGEST_REPLY));
  dec_ref_cnt(mess);
}

void RECOVERY_Deliver_Ckpt_Digest_Reply(signed_message *mess) {
  db_state_digest_reply_message *db_digest_reply, *next_db_digest_reply;
  int32u i, j, count;

  if(DATA.STATE.digest_ready == 1)
    return;

  db_digest_reply = (db_state_digest_reply_message *)(mess + 1);
  if(db_digest_reply->checkpoint_id == DATA.STATE.checkpoint_id) {
    if(DATA.STATE.reply[mess->machine_id] == NULL) {
      DATA.STATE.reply[mess->machine_id] = mess;
      inc_ref_cnt(mess);
      DATA.STATE.number_of_replies++;
      if(DATA.STATE.number_of_replies >= VAR.Faults + 1) {
        for(i = 1; i <= NUM_SERVERS - 1; i++) {
          if(DATA.STATE.reply[i] != NULL) {
            count = 1;
            db_digest_reply = (db_state_digest_reply_message *)(DATA.STATE.reply[i] + 1);
            for(j = 1; j <= NUM_SERVERS; j++) {
              if(i!=j && DATA.STATE.reply[j] != NULL) {
                next_db_digest_reply = (db_state_digest_reply_message *)(DATA.STATE.reply[j] + 1);
                if((db_digest_reply->state_size == next_db_digest_reply->state_size) &&
                    OPENSSL_RSA_Digests_Equal(db_digest_reply->digest, next_db_digest_reply->digest))
                  count++;
                if(count >= VAR.Faults + 1)
                  goto finish;
              }
            }
          }
        }
      }
    }
  }
  return;

  finish:
  // Update data structure based on the information provided by f+1 servers
  DATA.STATE.state_size = db_digest_reply->state_size;
  DATA.STATE.num_of_blocks = ceil((double)DATA.STATE.state_size/(BLOCK_SIZE));
  DATA.STATE.parts_per_data_block = ceil((double)(BLOCK_SIZE)/(PAYLOAD_SIZE));
  memcpy(DATA.STATE.received_digest, db_digest_reply->digest, DIGEST_SIZE);
  db_state_block = (data_block *)malloc(DATA.STATE.num_of_blocks * sizeof(data_block));
  block_transfer = (util_stopwatch *)malloc(DATA.STATE.num_of_blocks * sizeof(util_stopwatch));
  DATA.STATE.digest_ready = 1;
  for(i = 1; i <= NUM_SERVERS; i++) {
    if(DATA.STATE.reply[i] != NULL) {
      dec_ref_cnt(DATA.STATE.reply[i]);
      DATA.STATE.reply[i] = NULL;
    }
  }
  Alarm(DEBUG, "Found a valid digest of the database state.\n");
  if(OPENSSL_RSA_Digests_Equal(DATA.STATE.received_digest, DATA.STATE.digest)) {
    DATA.STATE.state_ready = 1;
    Alarm(PRINT, "The database state is correct.\n");
    UTIL_Stopwatch_Start(&BENCH.message_validation);
    RECOVERY_Catch_Up_Periodically(0, NULL);
  }
  else {
    Alarm(PRINT, "The database state is not correct. Start state transfer...\n");
    UTIL_Stopwatch_Start(&BENCH.state_transfer);
    DATA.recovery_in_progress = 1;
    RECOVERY_State_Transfer();
    RECOVERY_Check_ST_Periodically(0, NULL);
  }
}

// This function monitors if a given data block arrives before the expiration of a timeout.
// If not, recover the missing block (overcomes possible network faults...)
void RECOVERY_Check_ST_Periodically(int dummy, void *dummyp) {
  sp_time t;
  int32 curr_block, i, count = 0;
  double elapsed_time;

  if(DATA.STATE.state_ready == 1) return;

  // Check if the blacklist contains more than f servers.
  // In this case the timeout could be to low. Restore servers.
  for(i = 1; i <= NUM_SERVERS; i++)
    if(blacklist[i] == 1) 
      count++;
  if(count > VAR.Faults)
    for(i = 1; i <= NUM_SERVERS; i++)
      blacklist[i] = 0;

  curr_block = DATA.STATE.last_written_block + 1;
  for(i = curr_block; i < DATA.STATE.next_data_block; i++) {
    if(db_state_block[i].valid_block == 0) {
      UTIL_Stopwatch_Stop(&block_transfer[i]);
      elapsed_time = UTIL_Stopwatch_Elapsed(&block_transfer[i]);
      if(elapsed_time > (DATA_BLOCK_USEC / 1000000.0)) {
        RECOVERY_Retrieve_Single_Block(i);
      }
      else UTIL_Stopwatch_Start(&block_transfer[i]);
    }
    else RECOVERY_Write_On_Disk(i);
  }

  if(DATA.STATE.state_ready == 0) {
    t.sec  = STATE_TRANSFER_SEC;
    t.usec = STATE_TRANSFER_USEC;
    E_queue(RECOVERY_Check_ST_Periodically, 0, NULL, t);
  }
}

void RECOVERY_State_Transfer() {
  if(DATA.STATE.retrieved_data_blocks >= DATA.STATE.num_of_blocks)
    return;

  int32u block, i, next_sender = 1, count, current, last_block, digest_sender;
  int retrieve_this_time;

  retrieve_this_time = STATE_TRANSFER_MAX_LIMIT - DATA.STATE.transferring;
  if(DATA.STATE.next_data_block + retrieve_this_time > DATA.STATE.num_of_blocks) {
    last_block = DATA.STATE.num_of_blocks + 1;
    DATA.STATE.transferring += DATA.STATE.num_of_blocks - DATA.STATE.next_data_block;
  }
  else {
    last_block = DATA.STATE.next_data_block + retrieve_this_time;
    DATA.STATE.transferring = STATE_TRANSFER_MAX_LIMIT;
  }

  for(block = DATA.STATE.next_data_block; block < last_block; block++) {
    current = block - DATA.STATE.next_data_block;
    // Initialize data structure for state transfer
    db_state_block[block].block_number            = block;
    db_state_block[block].received_digest_replies = 0;
    db_state_block[block].current_part            = 0;
    db_state_block[block].block_ready             = 0;
    db_state_block[block].digest_ready            = 0;
    db_state_block[block].block_size              = 0;
    db_state_block[block].valid_block             = 0;
    db_state_block[block].compromised_block       = 1;
    db_state_block[block].state_sender_h          = 0;
    db_state_block[block].digest_sender_h         = 0;
    memset(db_state_block[block].block_digest, 0, DIGEST_SIZE);
    stdhash_construct(&(db_state_block[block].parts), sizeof(int32u), sizeof(db_state_part *), NULL, NULL, 0);

    // Set the senders of data blocks and the f senders of the digest
    for(i = 1; i <= NUM_SERVERS; i++)
      db_state_block[block].digest_reply[i] = NULL;

    do {
      next_sender = RECOVERY_Select_Server();
    } while((next_sender == VAR.My_Server_ID) || blacklist[next_sender] == 1);
    UTIL_Bitmap_Set(&db_state_block[block].state_sender_h, next_sender);
    count = 0;

    while(count < VAR.Faults) {
      do {
        digest_sender = RECOVERY_Select_Server();
      } while((digest_sender == VAR.My_Server_ID) || (digest_sender == next_sender) ||
               (blacklist[digest_sender] == 1) || (UTIL_Bitmap_Is_Set(&db_state_block[block].digest_sender_h, digest_sender) == 1));
      UTIL_Bitmap_Set(&db_state_block[block].digest_sender_h, digest_sender);
      count++;
    }
    UTIL_Stopwatch_Start(&block_transfer[block]);
    RECOVERY_Send_DB_State_Val_Request(DATA.STATE.checkpoint_id, block, db_state_block[block].digest_sender_h);
    RECOVERY_Send_DB_State_Tran_Request(DATA.STATE.checkpoint_id, block, db_state_block[block].state_sender_h);
  }
  DATA.STATE.next_data_block = last_block;
}

void RECOVERY_Retrieve_Single_Block(int32u block) {
  if(DATA.STATE.last_written_block >= DATA.STATE.num_of_blocks)
    return;

  int32u i, next_sender = 1, digest_sender, count = 0;

  // Blacklist the old block sender and choose a new sender
  if(db_state_block[block].block_ready == 0) {
    for(i = 1; i <= NUM_SERVERS; i++) {
      if(UTIL_Bitmap_Is_Set(&db_state_block[block].state_sender_h, i) == 1) {
        blacklist[i] = 1;
        UTIL_Bitmap_Clear(&db_state_block[block].state_sender_h, i);
        break;
      }
    }
    do {
      next_sender = RECOVERY_Select_Server();
    } while((next_sender == VAR.My_Server_ID) || (blacklist[next_sender] == 1) ||
            (UTIL_Bitmap_Is_Set(&db_state_block[block].digest_sender_h, next_sender) == 1));
    UTIL_Bitmap_Set(&db_state_block[block].state_sender_h, next_sender);
    RECOVERY_Send_DB_State_Tran_Request(DATA.STATE.checkpoint_id, block, db_state_block[block].state_sender_h);
  }

  // Blacklist the old digest sender(s) and choose new sender(s)
  if(db_state_block[block].digest_ready == 0) {
    for(i = 1; i <= NUM_SERVERS; i++) {
      if(UTIL_Bitmap_Is_Set(&db_state_block[block].digest_sender_h, i) == 1) {
        if(db_state_block[block].digest_reply[i] == NULL) {
          blacklist[i] = 1;
          UTIL_Bitmap_Clear(&db_state_block[block].digest_sender_h, i);
          count++;
        }
      }
    }
    i = 0;
    while(i < count) {
      do {
        digest_sender = RECOVERY_Select_Server();
        } while((digest_sender == VAR.My_Server_ID) || (digest_sender == next_sender) || (blacklist[next_sender] == 1) ||
                (UTIL_Bitmap_Is_Set(&db_state_block[block].digest_sender_h, digest_sender) == 1));
      UTIL_Bitmap_Set(&db_state_block[block].digest_sender_h, digest_sender);
      i++;
    }
    RECOVERY_Send_DB_State_Val_Request(DATA.STATE.checkpoint_id, block, db_state_block[block].digest_sender_h);
  }
  UTIL_Stopwatch_Start(&block_transfer[block]);   
}

void RECOVERY_Send_DB_State_Val_Request(int32u checkpoint_id, int32u data_block, int32u dest_bits) {
  signed_message *mess;

  Alarm(DEBUG, "Retrieving the digest of data block %d...\n", data_block);
  mess = RECOVERY_Construct_DB_State_Validation_Request_Message(checkpoint_id, data_block);
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(DB_STATE_VALIDATION_REQUEST));
  dec_ref_cnt(mess);
}

void RECOVERY_Deliver_DB_State_Val_Request(signed_message *mess) {
  db_state_validation_request_message *db_state_req;
  db_state_req = (db_state_validation_request_message *)(mess + 1);

  RECOVERY_Send_DB_State_Val_Reply(db_state_req->checkpoint_id, db_state_req->data_block, mess->machine_id);
}

void RECOVERY_Send_DB_State_Val_Reply(int32u checkpoint_id, int32u data_block, int32u sender_id) {
  signed_message *mess;
  int32u dest_bits = 0, read = 0;
  char buffer[BLOCK_SIZE];
  byte digest[DIGEST_SIZE];

  // Send a digest of the data block
  UTIL_Bitmap_Set(&dest_bits, sender_id);

  fseeko(DATA.STATE.fp, BLOCK_SIZE * (data_block - 1), SEEK_SET);
  read = fread(buffer, sizeof(char), BLOCK_SIZE, DATA.STATE.fp);
  OPENSSL_RSA_Make_Digest((byte *)buffer, read, digest);

  mess = RECOVERY_Construct_DB_State_Validation_Reply_Message(checkpoint_id, data_block, digest);
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(DB_STATE_VALIDATION_REPLY));
  dec_ref_cnt(mess);
  Alarm(DEBUG, "Digest of data block %d sent\n", data_block);
}

void RECOVERY_Deliver_DB_State_Val_Reply(signed_message *mess) {
  db_state_validation_reply_message *db_state_reply;
  int32u block;

  db_state_reply = (db_state_validation_reply_message *)(mess + 1);
  block          = db_state_reply->data_block;

  if(db_state_reply->checkpoint_id != DATA.STATE.checkpoint_id ||
     DATA.STATE.state_ready == 1 ||
     db_state_block[block].digest_ready == 1)
    return;

  if(db_state_block[block].digest_reply[mess->machine_id] == NULL) {
    Alarm(DEBUG, "Received a digest for data block %d from server %d\n", block, mess->machine_id);
    db_state_block[block].digest_reply[mess->machine_id] = mess;
    inc_ref_cnt(mess);
    db_state_block[block].received_digest_replies++;
    if(db_state_block[block].received_digest_replies >= VAR.Faults) {
      db_state_block[block].digest_ready = 1;
      RECOVERY_Validate_Block_Digest(block);
    }
  }
}

void RECOVERY_Validate_Block_Digest(int32u block) {
  db_state_validation_reply_message *db_state_reply;
  int32u count = 1, i;
  byte digest[DIGEST_SIZE];

  if(db_state_block[block].block_ready == 0 || db_state_block[block].digest_ready == 0) return;

  OPENSSL_RSA_Make_Digest((byte*)db_state_block[block].data_buffer, db_state_block[block].block_size, digest);
  for(i = 1; i <= NUM_SERVERS; i++) {
    if(db_state_block[block].digest_reply[i] != NULL) {
      db_state_reply = (db_state_validation_reply_message *)(db_state_block[block].digest_reply[i] + 1);
      if(OPENSSL_RSA_Digests_Equal(db_state_reply->digest, digest))
        count++;
    }
  }

  // The digest of the data block does not match the f received digests
  if(count < VAR.Faults + 1) {
    Alarm(PRINT, "State transfer of data block %d failed. Need to retrive the data block again.\n", block);
    free(db_state_block[block].data_buffer);
    db_state_block[block].current_part = 0;
    // TODO: blacklist malicious servers and retrieve the correct data block here
    return;
  }

  // The digest of the retrieved data block matches the f received digests
  memcpy(db_state_block[block].block_digest, digest, DIGEST_SIZE);
  for(i = 1; i <= NUM_SERVERS; i++) {
    if(db_state_block[block].digest_reply[i] != NULL) {
      dec_ref_cnt(db_state_block[block].digest_reply[i]);
      db_state_block[block].digest_reply[i] = NULL;
    }
  }
  db_state_block[block].valid_block = 1;
  UTIL_Stopwatch_Stop(&block_transfer[block]);
  RECOVERY_Write_On_Disk(block);
  RECOVERY_State_Transfer();
}

void RECOVERY_Send_DB_State_Tran_Request(int32u checkpoint_id, int32u data_block, int32u dest_bits) {
  signed_message *mess;

  Alarm(DEBUG, "Send a state transfer request for data block %d\n", data_block);
  mess = RECOVERY_Construct_DB_State_Transfer_Request_Message(checkpoint_id, data_block);
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(DB_STATE_TRANSFER_REQUEST));
  dec_ref_cnt(mess);
}

void RECOVERY_Deliver_DB_State_Tran_Request(signed_message *mess) {
  db_state_transfer_request_message *db_state_req;
  db_state_req = (db_state_transfer_request_message *)(mess + 1);

  Alarm(DEBUG, "State transfer request for data block %d\n", db_state_req->data_block);
  RECOVERY_Send_DB_State_Tran_Reply(db_state_req->checkpoint_id, db_state_req->data_block, mess->machine_id);
}

void RECOVERY_Send_DB_State_Tran_Reply(int32u checkpoint_id, int32u data_block, int32u sender) {
  signed_message *mess;
  int32u send_now, already_sent = 0, read = 0;
  char buffer[PAYLOAD_SIZE];
  int32u dest_bits = 0, part = 0;

  fseeko(DATA.STATE.fp, BLOCK_SIZE * (data_block - 1), SEEK_SET);
  UTIL_Bitmap_Set(&dest_bits, sender);

  while(part < DATA.STATE.parts_per_data_block) {
    if(already_sent + PAYLOAD_SIZE <= BLOCK_SIZE)
      send_now = PAYLOAD_SIZE;
    else send_now = BLOCK_SIZE - already_sent;
    read = fread(buffer, sizeof(char), send_now, DATA.STATE.fp);
    already_sent += read;
    part++;
    mess = RECOVERY_Construct_DB_State_Transfer_Reply_Message(checkpoint_id, part, data_block, buffer, read);
    SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(DB_STATE_TRANSFER_REPLY));
    dec_ref_cnt(mess);
    memset(buffer, 0, PAYLOAD_SIZE);
  }
  Alarm(DEBUG, "%d parts sent\n", part);
}

void RECOVERY_Deliver_DB_State_Tran_Reply(signed_message *mess) {
  db_state_transfer_reply_message *db_state_reply;
  db_state_part *st_part;
  off_t offset = 0;
  int32u i, block;
	
  db_state_reply = (db_state_transfer_reply_message *)(mess + 1);
  block          = db_state_reply->data_block;

  // Check if the data block is already complete
  if(db_state_block[block].block_ready == 1) {
    Alarm(DEBUG, "Data block %d already received\n", block);
    return;
  }

  // Check if the received message belongs to the correct checkpoint
  if(db_state_reply->checkpoint_id != DATA.STATE.checkpoint_id) {
    Alarm(DEBUG, "Bad checkpoint id %d for block %d\n", db_state_reply->checkpoint_id, block);
    return;
  }

  //Check if the message is already been received
  if(RECOVERY_Get_DB_State_Part_If_Exists(block, db_state_reply->part)) {
    Alarm(DEBUG, "Part already received for block %d\n", block);
    return;
  }

  // Check if the sender is authorized to send state
  if(UTIL_Bitmap_Is_Set(&db_state_block[block].state_sender_h, mess->machine_id) == 1)
    goto message_accepted;
  Alarm(DEBUG, "Unauthorized server %d for block %d. The message will be discarded\n", mess->machine_id, block);
  return;

  // Here the state message has been accepted
  message_accepted:
  st_part                = RECOVERY_Get_DB_State_Part(block, db_state_reply->part);
  st_part->checkpoint_id = db_state_reply->checkpoint_id;
  st_part->part          = db_state_reply->part;
  st_part->state_part    = mess;
  inc_ref_cnt(mess);

  db_state_block[block].block_size += db_state_reply->bytes;
  db_state_block[block].current_part++;
  // If all the parts have been collected reconstruct the data block and store it on stable storage
  if(db_state_block[block].current_part == DATA.STATE.parts_per_data_block) {
    db_state_block[block].data_buffer = (char *)malloc(db_state_block[block].block_size);
    for(i = 1; i <= DATA.STATE.parts_per_data_block; i++) {
      st_part = RECOVERY_Get_DB_State_Part_If_Exists(block, i);
      db_state_reply = (db_state_transfer_reply_message *)(st_part->state_part + 1);
      if(db_state_reply->bytes > 0) {
        memcpy(db_state_block[block].data_buffer + offset, (char *)(db_state_reply + 1), db_state_reply->bytes);
        offset += db_state_reply->bytes;
      }
      dec_ref_cnt(st_part->state_part);
    }
    Alarm(DEBUG, "Data block %d received\n", block);
    db_state_block[block].block_ready = 1;
    RECOVERY_Validate_Block_Digest(block);
  }
}

void RECOVERY_Write_On_Disk(int32u block) {
  int32u lw, i;

  if(block == DATA.STATE.last_written_block)
    return;

  lw = DATA.STATE.last_written_block + 1;
  for(i = lw; i <= block; i++) {
    if(db_state_block[i].valid_block == 0)
      break;
    fseeko(output_state, BLOCK_SIZE * (i - 1), SEEK_SET);
    fwrite(db_state_block[i].data_buffer, 1, db_state_block[i].block_size, output_state);
    free(db_state_block[i].data_buffer);
    db_state_block[i].data_buffer = NULL;
    DATA.STATE.last_written_block = i;
    Alarm(PRINT, "Data block %d succesfully retrieved.\n", i);
    DATA.STATE.retrieved_data_blocks += 1;
    DATA.STATE.transferring -= 1;
  }

  if(DATA.STATE.last_written_block == DATA.STATE.num_of_blocks) {
    UTIL_Stopwatch_Stop(&BENCH.state_transfer);
    DATA.STATE.state_ready = 1;
    fclose(output_state);
    Alarm(PRINT, "Valid database state retrieved. State transfer completed.\n\n");
    UTIL_Stopwatch_Start(&BENCH.message_validation);
    RECOVERY_Catch_Up_Periodically(0, NULL);
  } 
}

/********************************
 * PRIME CERTIFICATE VALIDATION *
 ********************************/

void RECOVERY_Initialize_Catch_Up_Struct() {
  DATA.CAT.replies            = 0;
  DATA.CAT.complete           = 0;
  DATA.CAT.rec_point          = 0;
  DATA.CAT.last_buffered_mess = 0;

  memset(DATA.CAT.seq_num, 0, sizeof(int32u) * NUM_SERVER_SLOTS);
  memset(DATA.CAT.view, 0, sizeof(int32u) * NUM_SERVER_SLOTS);
  memset(DATA.CAT.aru, 0, sizeof(int32u) * NUM_SERVER_SLOTS);
  memset(DATA.CAT.temp_aru, 0, sizeof(int32u) * NUM_SERVER_SLOTS * NUM_SERVER_SLOTS);
}

void RECOVERY_Catch_Up_Periodically(int dummy, void *dummyp) {
  signed_message *mess;
  sp_time t;
  int32u i, dest_bits = 0;

  if(DATA.CAT.complete == 1)
    return;

  for(i = 1; i <= NUM_SERVERS; i++)
    if(i != VAR.My_Server_ID)
      UTIL_Bitmap_Set(&dest_bits, i);

  mess = RECOVERY_Construct_Catch_Up_Message();
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(CATCH_UP));
  dec_ref_cnt(mess);
  DATA.recovery_in_progress = 0;
  DATA.buffering_during_recovery = 1;

  t.sec  = 0;
  t.usec = 500000;
  E_queue(RECOVERY_Catch_Up_Periodically, 0, NULL, t);
}

void RECOVERY_Deliver_Catch_Up(signed_message *mess) {
  Alarm(DEBUG, "CATCH_UP message received from server %d\n", mess->machine_id);
  RECOVERY_Send_Catch_Up_Reply(mess->machine_id);
}

void RECOVERY_Send_Catch_Up_Reply(int32u srv_id) {
  signed_message *mess;
  int32u dest_bits = 0;

  UTIL_Bitmap_Set(&dest_bits, srv_id);

  mess = RECOVERY_Construct_Catch_Up_Reply_Message(DATA.View, DATA.ORD.ARU, DATA.PO.aru);
  SIG_Add_To_Pending_Messages(mess, dest_bits, UTIL_Get_Timeliness(CATCH_UP_REPLY));
  dec_ref_cnt(mess);
}

void RECOVERY_Deliver_Catch_Up_Reply(signed_message *mess){
  catch_up_reply_message *catch_up;
  int32u i, j, temp[NUM_SERVER_SLOTS];

  if(DATA.CAT.complete == 1)
    return;

  catch_up = (catch_up_reply_message *)(mess + 1);

  if(DATA.CAT.seq_num[mess->machine_id] == 0) {
    DATA.CAT.seq_num[mess->machine_id] = catch_up->seq_num;
    DATA.CAT.view[mess->machine_id] = catch_up->view;
    for(i = 1; i <= NUM_SERVERS; i++)
      DATA.CAT.temp_aru[mess->machine_id][i] = catch_up->aru[i];
    DATA.CAT.replies++;
    if(DATA.CAT.replies >= 2 * VAR.Faults + 1) {
      // Select the 2f+1th sequence number
      qsort((void*)(DATA.CAT.seq_num + 1), NUM_SERVERS, sizeof(int32u), intcmp);
      DATA.CAT.rec_point = DATA.CAT.seq_num[1 + 2*VAR.Faults+1];
      if(DATA.CAT.rec_point > DATA.ORD.ARU || DATA.ORD.ARU == 0) {
        // Select the 2f+1th view number
        qsort((void*)(DATA.CAT.view + 1), NUM_SERVERS, sizeof(int32u), intcmp);
        DATA.View = DATA.CAT.view[1 + 2*VAR.Faults+1];
        // For each server select the 2f+1th po_aru number
        for(i = 1; i < NUM_SERVER_SLOTS; i++) {
          for(j = 1; j < NUM_SERVER_SLOTS; j++)
            temp[j] = DATA.CAT.temp_aru[j][i];
          qsort((void*)(temp + 1), NUM_SERVERS, sizeof(int32u), intcmp);
          DATA.CAT.aru[i] = temp[1 + 2*VAR.Faults+1];
        }
        DATA.PO.po_seq_num = DATA.CAT.aru[VAR.My_Server_ID] + 1;  
        DATA.CAT.complete = 1;
        Alarm(PRINT, "Found a recovery point: sequence number %d\n", DATA.CAT.rec_point);
        RECOVERY_Validate_Order_Messages();
      }
    }
  }
}

// Validate order certificates and retrieve missing ones
void RECOVERY_Validate_Order_Messages() {
  int32u count, msgcount, sn;
  ord_slot *slot;
  complete_pre_prepare_message *pp;
  signed_message **prepare;
  signed_message **commit;

  stdhash_construct(&Retrieved_ORD_Cert, sizeof(int32u), sizeof(retrieved_cert *), NULL, NULL, 0);

  for(msgcount = DATA.ORD.ARU + 1; msgcount <= DATA.CAT.rec_point; msgcount++) {
    slot = UTIL_Get_ORD_Slot_If_Exists(msgcount);
    if(slot == NULL) {
      RECOVERY_Retrieve_ORD_Cert(msgcount);
      continue;
    }
    if(slot->executed == 1)
      continue;
    pp      = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
    prepare = (signed_message **)&(slot->prepare_certificate.prepare);
    commit  = (signed_message **)&(slot->commit_certificate.commit);

    // Validate prepare certificate
    count = 0;
    for(sn = 1; sn <= NUM_SERVERS; sn++) {
      if(prepare[sn] != NULL) {
        if(RECOVERY_Verify_Prepare_Cert(prepare[sn], pp))
          count++;
        else Alarm(PRINT, "PREPARE didn't match PRE-PREPARE while checking for prepare certificate.\n");
      }
    }
    // If we have the Pre-Prepare and 2f Prepares, we're good to go
    if(count < VAR.Faults * 2) {
      Alarm(PRINT, "Prepare certificate not valid for message %d. Need to retrieve the correct one.\n", msgcount);
      RECOVERY_Retrieve_ORD_Cert(msgcount);
      continue;
    }
    else Alarm(DEBUG, "Prepare certificate valid.\n");

    // Validate commit certificate
    count = 0;
    for(sn = 1; sn <= NUM_SERVERS; sn++) {
      if(commit[sn] != NULL) {
        if(RECOVERY_Verify_Commit_Cert(commit[sn], pp))
          count++;
        else Alarm(PRINT, "PREPARE didn't match COMMIT while checking for commit certificate.\n");
      }
    }
    // If we have 2f+1 Commits, we're good to go
    if(count < VAR.Faults * 2 + 1) {
      Alarm(PRINT, "Commit certificate not valid for message %d. Need to retrieve the correct one.\n", msgcount);
      RECOVERY_Retrieve_ORD_Cert(msgcount);
    }
    else Alarm(DEBUG, "Commit certificate valid.\n");
  }

  stdhash_begin(&Retrieved_ORD_Cert, &ORD_iterator);
  RECOVERY_Send_ORD_Cert_Request();
}

// Validate pre-order certificates
void RECOVERY_Validate_PO_Messages() {
  int32u srv_id, sn, aru, p, pcount, failed = 0, i, po_request_len;  
  po_slot *slot;
  signed_message *po_request;
  signed_message **po_ack;
  po_ack_message *po_ack_specific;
  po_ack_part *part;
  byte digest[DIGEST_SIZE];
    
  for(i = 1; i <= NUM_SERVERS; i++)
    stdhash_construct(&Retrieved_PO_Cert[i], sizeof(int32u), sizeof(retrieved_cert *), NULL, NULL, 0);

  for(srv_id = 1; srv_id <= NUM_SERVERS; srv_id++) {
    for(aru = DATA.PO.max_acked[srv_id] + 1; aru <= DATA.CAT.aru[srv_id]; aru++) {
    /* Retrieve PO-REQUEST and PO-ACK from the po_slot */
    slot = UTIL_Get_PO_Slot_If_Exists(srv_id, aru);
    if(slot == NULL) {
      RECOVERY_Retrieve_PO_Cert(srv_id, aru);
      continue;
    }
    if(slot->executed == 1)
      continue;
    po_request = slot->po_request;
    if(po_request == NULL || slot->ack_count < 2 * VAR.Faults + 1) {
      RECOVERY_Retrieve_PO_Cert(srv_id, aru);
      continue;
    }
    po_ack = (signed_message **)&(slot->po_ack);
			
    /* Compute a digest of the PO-REQUEST message */
    po_request_len = (sizeof(signed_message) + po_request->len + MT_Digests_(po_request->mt_num) * DIGEST_SIZE);
    OPENSSL_RSA_Make_Digest((byte*)po_request, po_request_len, digest);
			
      /* Verify digests contained in PO-ACKs */
      for(sn = 1; sn <= NUM_SERVERS; sn++) {
        pcount = 0;
        if(po_ack[sn] != NULL) {
          po_ack_specific = (po_ack_message *)(po_ack[sn] + 1);
          part = (po_ack_part *)(po_ack_specific + 1);
            for (p = 0; p < po_ack_specific->num_ack_parts; p++) {
              if(OPENSSL_RSA_Digests_Equal(digest, part[p].digest))
                pcount++;
            }
          if(pcount < po_ack_specific->num_ack_parts) {
            failed = 1;
            dec_ref_cnt(po_ack[sn]);
            break;
          }
        }
      }
      if(failed == 1) {
        Alarm(PRINT, "Pre_order certificate not valid\n");
        failed = 0;
        RECOVERY_Retrieve_PO_Cert(srv_id, aru);
      }
    }
    stdhash_begin(&Retrieved_PO_Cert[srv_id], &PO_iterator[srv_id]);
  }
  RECOVERY_Send_PO_Cert_Request();
}

void RECOVERY_Retrieve_ORD_Cert(int32u pc_seq_num) {
  retrieved_cert *cert;

  /* Get the certificate */
  cert                    = RECOVERY_Get_ORD_Cert(pc_seq_num);
  cert->seq_num           = pc_seq_num;
  cert->received_replies  = 0;
  cert->certificate_ready = 0;
  cert->validating        = 0;
  cert->val_attempt       = 0;
  cert->bitmask           = 0;
}

void RECOVERY_Send_ORD_Cert_Request() {
  retrieved_cert *cert;
  signed_message *ord_cert;
  int32u dest_bits = 0, i, count = 0;

  if(stdhash_is_end(&Retrieved_ORD_Cert, &ORD_iterator)) {
    RECOVERY_Validate_PO_Messages();
    return;
  }
  cert = *((retrieved_cert**)stdhash_it_val(&ORD_iterator));
  ord_cert = RECOVERY_Construct_Ord_Cert_Message(cert->seq_num, 1);

  while(count < VAR.Faults + 1) {
    do {
      i = RECOVERY_Select_Server();
    } while((i == VAR.My_Server_ID) || (UTIL_Bitmap_Is_Set(&dest_bits, i) == 1));
    UTIL_Bitmap_Set(&dest_bits, i);
    count++;
  }

  SIG_Add_To_Pending_Messages(ord_cert, dest_bits, UTIL_Get_Timeliness(ORD_CERT));
  dec_ref_cnt(ord_cert);
  Alarm(DEBUG, "Retrieve valid prepare and commit certificates\n");
}

void RECOVERY_Deliver_ORD_Cert_Request(signed_message *mess) {
  ord_slot *slot;
  ord_cert_message *cert_specific;
  signed_message *cert_reply;
  int32u i, dest_bits = 0, count = 0, offset = 0;
  char cert[PRIME_MAX_PACKET_SIZE];
	
  cert_specific = (ord_cert_message *)(mess + 1);
  slot          = UTIL_Get_ORD_Slot_If_Exists(cert_specific->seq_num);

  if(slot == NULL) {
    Alarm(PRINT, "Ord slot %d doesn't exist!\n", cert_specific->seq_num);
    return;
  }

  // Copy PREPARE messages in the buffer
  for(i = 1; i <= NUM_SERVERS; i++)
    if(count < 2 * VAR.Faults && slot->prepare_certificate.prepare[i] != NULL) {
      memcpy(cert + offset, slot->prepare_certificate.prepare[i], UTIL_Message_Size(slot->prepare_certificate.prepare[i]));
      offset += UTIL_Message_Size(slot->prepare_certificate.prepare[i]);
      count++;
    }
  // Copy COMMIT messages in the buffer
  count = 0;
  for(i = 1; i <= NUM_SERVERS; i++)
    if(count < 2 * VAR.Faults + 1 && slot->commit_certificate.commit[i] != NULL) {
      memcpy(cert + offset, slot->commit_certificate.commit[i], UTIL_Message_Size(slot->commit_certificate.commit[i]));
      offset += UTIL_Message_Size(slot->commit_certificate.commit[i]);
      count++;
    }

  UTIL_Bitmap_Set(&dest_bits, mess->machine_id);
  cert_reply = RECOVERY_Construct_Ord_Cert_Reply_Message(cert_specific->seq_num, cert_specific->view, cert, offset, slot->complete_pre_prepare);
  Alarm(DEBUG, "Sending a prepare certificate\n");
  SIG_Add_To_Pending_Messages(cert_reply, dest_bits, UTIL_Get_Timeliness(ORD_CERT_REPLY));
  dec_ref_cnt(cert_reply);
}

void RECOVERY_Deliver_ORD_Cert_Reply(signed_message *cert_reply) {
  retrieved_cert *cert;
  ord_cert_reply_message *cert_reply_specific;

  cert_reply_specific = (ord_cert_reply_message *)(cert_reply + 1);
  cert                = RECOVERY_Get_ORD_Cert_If_Exists(cert_reply_specific->seq_num);

  if(cert->certificate_ready == 1)
    return;

  if(cert->reply[cert_reply->machine_id] == NULL) {
    cert->reply[cert_reply->machine_id] = cert_reply;
    inc_ref_cnt(cert_reply);
    cert->received_replies++;
    if(cert->validating == 0) {
      cert->validating = 1;
      RECOVERY_Verify_ORD_Cert(cert->seq_num);
    }
  }
}

void RECOVERY_Verify_ORD_Cert(int32u seq_num) {
  retrieved_cert *cert;
  signed_message *mess;
  ord_slot *slot;
  complete_pre_prepare_message pre_prepare;
  ord_cert_reply_message *cert_specific;
  int32u i, count, pcount, size;

  cert = RECOVERY_Get_ORD_Cert_If_Exists(seq_num);
  if(cert == NULL)
    return;
  if(cert->certificate_ready == 1)
    return;
  // Validate an order certificate only if it has not been validated before
  for(i = 1; i <= NUM_SERVERS; i++) {
    if(cert->reply[i] != NULL && !UTIL_Bitmap_Is_Set(&cert->bitmask, i)) {
      cert_specific = (ord_cert_reply_message *)(cert->reply[i] + 1);
      UTIL_Bitmap_Set(&cert->bitmask, i);
      cert->val_attempt++;
      pre_prepare = cert_specific->pre_prepare;
      mess = (signed_message*)(cert_specific + 1);
      // Prepare certificates
      count = 0;
      pcount = 0;
      while (count < 2 * VAR.Faults) {
          size = UTIL_Message_Size(mess);
          if(RECOVERY_Verify_Prepare_Cert(mess, &pre_prepare))
            pcount++;
          mess = (signed_message*)((char*)mess + size);
        count++;
      }
      if(pcount < 2 * VAR.Faults) {
        if(cert->val_attempt < cert->received_replies)
          continue;
        else {
          // If at least f+1 servers replied but we still
          // didn't receive a correct certificate ask again
          goto retry;
        }
      }
      // Commit certificates 
      count = 0;
      pcount = 0;
      while(count < 2 * VAR.Faults + 1) {
          size = UTIL_Message_Size(mess);
          if(RECOVERY_Verify_Commit_Cert(mess, &pre_prepare))
            pcount++;
          mess = (signed_message*)((char*)mess + size);
        count++;
      }
      if(pcount >= 2 * VAR.Faults + 1) {
        Alarm(PRINT, "Valid prepare and commit certificates found for pre_prepare %d\n", seq_num);
        cert->certificate_ready = 1;

        // Before applying the retrieved slot, verify that is not in the pending list
        slot = UTIL_Get_Pending_ORD_Slot_If_Exists(seq_num);
        if(slot == NULL) {
          // Ready to apply the correct prepare and commit certificates to the ord_slot
          slot = UTIL_Get_ORD_Slot(seq_num);
          slot->complete_pre_prepare = cert_specific->pre_prepare;
          slot->collected_all_parts = 1;
          slot->should_handle_complete_pre_prepare = 0;
          slot->prepare_certificate_ready = 1;
          // Copy the completed Pre-Prepare into the Prepare Certificate
          memcpy(&slot->prepare_certificate.pre_prepare, &slot->complete_pre_prepare, sizeof(complete_pre_prepare_message));
          // Copy the prepare messages
          mess = (signed_message*)(cert_specific + 1);
          count = 0;
          while (count < 2 * VAR.Faults) {
            size = UTIL_Message_Size(mess);
            slot->prepare_certificate.prepare[mess->machine_id] = mess;
            mess = (signed_message*)((char*)mess + size);
            count++;
          }
          // Copy the commit messages
          count = 0;
          while (count < 2 * VAR.Faults + 1) {
            size = UTIL_Message_Size(mess);
            slot->commit_certificate.commit[mess->machine_id] = mess;
            mess = (signed_message*)((char*)mess + size);
            count++;
          }
        }
        stdhash_it_next(&ORD_iterator);
        RECOVERY_Send_ORD_Cert_Request();
        return;
      }
      else {
        // If at least f+1 servers replied but we still
        // didn't receive a correct certificate ask again
        if(cert->val_attempt == cert->received_replies)
          goto retry;
        cert->validating = 0;
        return;
      }
    }
  }

  retry:
  Alarm(PRINT, "Retry to tranfer certificate with sequence number %d\n", seq_num);
  stdhash_erase_key(&Retrieved_ORD_Cert, &seq_num);
  RECOVERY_Retrieve_ORD_Cert(seq_num);
  RECOVERY_Send_ORD_Cert_Request();
}

void RECOVERY_Retrieve_PO_Cert(int32u srv_id, int32u po_seq_num) {
  retrieved_cert *cert;

  /* Get the certificate */
  cert                    = RECOVERY_Get_PO_Cert(srv_id, po_seq_num);
  cert->seq_num           = po_seq_num;
  cert->server_id         = srv_id;
  cert->received_replies  = 0;
  cert->certificate_ready = 0;
}

void RECOVERY_Send_PO_Cert_Request() {
  retrieved_cert *cert;
  signed_message *po_cert;
  int32u dest_bits = 0, i, count = 0;

  while(stdhash_is_end(&Retrieved_PO_Cert[PO_Index], &PO_iterator[PO_Index])) {
    if(PO_Index == NUM_SERVERS) {
      RECOVERY_Execute_ORD_Cert();
      RECOVERY_Cleanup();
      return;
    }
    else PO_Index++;
  }

  cert = *((retrieved_cert**)stdhash_it_val(&PO_iterator[PO_Index]));
  po_cert = RECOVERY_Construct_PO_Cert_Message(cert->server_id ,cert->seq_num);

  while(count < 2 * VAR.Faults + 1) {
    do {
      i = RECOVERY_Select_Server();
    } while((i == VAR.My_Server_ID) || (UTIL_Bitmap_Is_Set(&dest_bits, i) == 1));
    UTIL_Bitmap_Set(&dest_bits, i);
    count++;
  }

  SIG_Add_To_Pending_Messages(po_cert, dest_bits, UTIL_Get_Timeliness(PO_CERT));
  dec_ref_cnt(po_cert);
  Alarm(DEBUG, "Retrieve valid pre_order certificate\n");
}

void RECOVERY_Deliver_PO_Cert_Request(signed_message *mess) {
  po_slot *slot;
  po_cert_message *cert_specific;
  signed_message *cert_reply;
  int size;
  int32u dest_bits = 0;
  char upd[PRIME_MAX_PACKET_SIZE];

  cert_specific = (po_cert_message *)(mess + 1);
  slot          = UTIL_Get_PO_Slot_If_Exists(cert_specific->server_id, cert_specific->seq_num);

  if(slot == NULL) {
    Alarm(PRINT, "PO slot %d, %d doesn't exist\n", cert_specific->server_id, cert_specific->seq_num);
    return;
  }
  if(slot->po_request == NULL)
    return;

  // Copy PO-REQUEST message in the buffer
  size = UTIL_Message_Size(slot->po_request);
  memcpy(upd, slot->po_request, size);

  UTIL_Bitmap_Set(&dest_bits, mess->machine_id);
  cert_reply = RECOVERY_Construct_PO_Cert_Reply_Message(cert_specific->server_id, cert_specific->seq_num, upd, slot->ack_count, size);
  Alarm(DEBUG, "Sending a pre_order certificate\n");
  SIG_Add_To_Pending_Messages(cert_reply, dest_bits, UTIL_Get_Timeliness(PO_CERT_REPLY));
  dec_ref_cnt(cert_reply);
}

void RECOVERY_Deliver_PO_Cert_Reply(signed_message *cert_reply) {
  retrieved_cert *cert;
  po_cert_reply_message *cert_reply_specific;

  cert_reply_specific = (po_cert_reply_message *)(cert_reply + 1);
  cert                = RECOVERY_Get_PO_Cert_If_Exists(cert_reply_specific->server_id, cert_reply_specific->seq_num);

  if(cert->certificate_ready == 1)
    return;
  if(cert->reply[cert_reply->machine_id] == NULL) {
    cert->reply[cert_reply->machine_id] = cert_reply;
    inc_ref_cnt(cert_reply);
    cert->received_replies++;
      if(cert->received_replies >= VAR.Faults + 1) {
        if(RECOVERY_Verify_PO_Cert(cert->reply)) {
          Alarm(PRINT, "Valid pre_order certificate found for update %d injected by %d\n", cert_reply_specific->seq_num, cert_reply_specific->server_id);
          cert->certificate_ready = 1;
          stdhash_it_next(&PO_iterator[PO_Index]);
          RECOVERY_Send_PO_Cert_Request();
      }
    }
  }
}

int32u RECOVERY_Verify_PO_Cert(signed_message *reply[]) {
  int32u i, j, count, po_request_len;
  signed_message *po_request, *next_po_request;
  po_cert_reply_message *cert_reply_specific, *next_cert_reply_specific;
  byte digest[DIGEST_SIZE], next_digest[DIGEST_SIZE];
  po_slot *slot;

  // Validate PO-REQUEST
  for(i = 1; i <= NUM_SERVERS - 1; i++) {
    // Compute the digest of the PO-REQUEST
    if(reply[i] != NULL) {
      cert_reply_specific = (po_cert_reply_message *)(reply[i] + 1);
      if(cert_reply_specific->ack_count < 2 * VAR.Faults + 1)
        continue;
      po_request = (signed_message *)(cert_reply_specific + 1);
      po_request_len = (sizeof(signed_message) + po_request->len + MT_Digests_(po_request->mt_num) * DIGEST_SIZE);
      OPENSSL_RSA_Make_Digest((byte*)po_request, po_request_len, digest);
      // Compute the digest of the next PO-REQUEST
      count = 1;
      for(j = 1; j <= NUM_SERVERS; j++) {
        if(i != j && reply[j] != NULL) {
          next_cert_reply_specific = (po_cert_reply_message *)(reply[j] + 1);
          if(next_cert_reply_specific->ack_count < 2 * VAR.Faults + 1)
            continue;
          next_po_request = (signed_message *)(next_cert_reply_specific + 1);
          po_request_len = (sizeof(signed_message) + next_po_request->len + MT_Digests_(next_po_request->mt_num) * DIGEST_SIZE);
          OPENSSL_RSA_Make_Digest((byte*)next_po_request, po_request_len, next_digest);
          // Compare digests
          if(OPENSSL_RSA_Digests_Equal(digest, next_digest))
            count++;
          if(count >= VAR.Faults + 1) {
            // Apply the correct PO-REQUEST to data structure
            slot = UTIL_Get_PO_Slot(cert_reply_specific->server_id, cert_reply_specific->seq_num);
            slot->seq_num = cert_reply_specific->seq_num;
            slot->po_request = (signed_message *)malloc(UTIL_Message_Size(po_request));
            memcpy(slot->po_request, po_request, UTIL_Message_Size(po_request));
            slot->ack_count = cert_reply_specific->ack_count;
            goto finish;
          }
        }
      }
    }
  }
  return 0;
	
  finish:
  for(i = 1; i <= NUM_SERVERS - 1; i++)
    dec_ref_cnt(reply[i]);
  return 1;
}

int32u RECOVERY_Verify_Prepare_Cert(signed_message *prepare, complete_pre_prepare_message *pp) {
  prepare_message *prepare_specific;
  byte digest[DIGEST_SIZE + 1];
  prepare_specific = (prepare_message *)(prepare + 1);

  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);
  if(!OPENSSL_RSA_Digests_Equal(digest, prepare_specific->digest)) {
    Alarm(PRINT, "Prepare: digests don't match for message %d.\n", pp->seq_num);
    Alarm(PRINT, "Pre_prepare digest: ");
    RECOVERY_Print_Digest(digest);
    Alarm(PRINT, "Prepare digest: ");
    RECOVERY_Print_Digest(prepare_specific->digest);
    return 0;
  }
  return 1;
}

int32u RECOVERY_Verify_Commit_Cert(signed_message *commit, complete_pre_prepare_message *pp) {
  commit_message *commit_specific;
  byte digest[DIGEST_SIZE + 1];
  commit_specific = (commit_message*)(commit + 1);

  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);
  if(!OPENSSL_RSA_Digests_Equal(digest, commit_specific->digest)) {
    Alarm(PRINT, "Commit: digests don't match.\n");
    return 0;
  }
  return 1;
}

void RECOVERY_Execute_ORD_Cert() {
  ord_slot *slot;
  complete_pre_prepare_message *complete_pp;
  po_aru_signed_message *cum_acks;
  signed_message *po_aru;
  po_aru_message *po_aru_specific;
  int32u i;
  int32u latest_po_aru_from_server[NUM_SERVERS];

  DATA.execute_batch = 1;
  i = DATA.ORD.ARU + 1;
  for(; i <= DATA.CAT.rec_point; i++) {
    // Verify if the slot exists or if it is in the pending list
    slot = UTIL_Get_ORD_Slot_If_Exists(i);
    if(slot == NULL)
      slot = UTIL_Get_Pending_ORD_Slot_If_Exists(i);
    if(slot == NULL) {
      Alarm(PRINT, "Slot %d null\n", i);
      continue;
    }
    if(i == DATA.ORD.ARU + 1) {
      ORDER_Execute_Commit(slot);
      // Remove the slot from the pending list, if any
      slot = UTIL_Get_Pending_ORD_Slot_If_Exists(i);
      if(slot != NULL) {
        stdhash_erase_key(&DATA.ORD.Pending_Execution, &i);
        dec_ref_cnt(slot);
      }
    }
    else Alarm(PRINT, "Expected ARU %d, found slot %d\n", DATA.ORD.ARU + 1, i);
  }
  Alarm(DEBUG, "Last buffered %d\n", DATA.CAT.last_buffered_mess);
  DATA.buffering_during_recovery = 0;
  for(i = DATA.CAT.rec_point + 1; i <= DATA.CAT.last_buffered_mess; i++)
    ORDER_Attempt_To_Execute_Pending_Commits(0, 0);
  DATA.execute_batch = 0;

  // Update PO_ARU
  slot = UTIL_Get_ORD_Slot_If_Exists(DATA.CAT.last_buffered_mess);
  if(slot == NULL)
    return;
  complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
  cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;
  for(i = 0; i < NUM_SERVERS; i++) {
    po_aru = (signed_message *)&cum_acks[i];
    if(po_aru->type == PO_ARU) {
      po_aru_specific = (po_aru_message *)(po_aru + 1);
      latest_po_aru_from_server[i] = po_aru_specific->num;
      APPLY_Message_To_Data_Structs(po_aru);
    }
  }
  // Update the DATA.PO.po_aru_num based on the received PO_ACKs
  qsort((void*)(latest_po_aru_from_server), NUM_SERVERS, sizeof(int32u), intcmp);
  DATA.PO.po_aru_num = latest_po_aru_from_server[VAR.Faults + 1] + 1;
  PRE_ORDER_Send_PO_ARU();
}

retrieved_cert* RECOVERY_Get_ORD_Cert(int32u seq_num) {
  retrieved_cert *cert;
  stdhash *h;
  stdit it;

  h = &Retrieved_ORD_Cert;
	
  stdhash_find(h, &it, &seq_num);
  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it)) {
  /* Allocate memory for a slot. */
  if((cert = (retrieved_cert *)new_ref_cnt(RET_CERT_OBJ)) == NULL)
    Alarm(EXIT,"Could not allocate memory for ret ord cert.\n");
    /* insert this slot in the hash */
    memset((void*)cert, 0, sizeof(retrieved_cert));
    cert->seq_num = seq_num;
    stdhash_insert(h, NULL, &seq_num, &cert);
  }
  else cert = *((retrieved_cert**)stdhash_it_val(&it));

  return cert;
}

retrieved_cert* RECOVERY_Get_ORD_Cert_If_Exists(int32u seq_num) {
  retrieved_cert *cert;
  stdhash *h;
  stdit it;
	
  h = &Retrieved_ORD_Cert;
  cert = NULL;
  stdhash_find(h, &it, &seq_num);
  /* If there is nothing in the slot, then create a slot. */
  if(!stdhash_is_end(h, &it))
    cert = *((retrieved_cert**)stdhash_it_val(&it));

  return cert;
}

retrieved_cert* RECOVERY_Get_PO_Cert(int32u server_id, int32u seq_num) {
  retrieved_cert *cert;
  stdit it;
  stdhash *h;

  h = &Retrieved_PO_Cert[server_id];

  stdhash_find(h, &it, &seq_num);
  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it)) {

  /* Allocate memory for a slot. */
  if((cert = (retrieved_cert *) new_ref_cnt(RET_CERT_OBJ)) == NULL)
    Alarm(EXIT, "Could not allocate memory for ret po cert.\n");
    memset((void*)cert, 0, sizeof(cert));
    /* insert this cert in the hash */
    stdhash_insert(h, NULL, &seq_num, &cert);
  }
  else cert = *((retrieved_cert**)stdhash_it_val(&it));

  return cert;
}

retrieved_cert* RECOVERY_Get_PO_Cert_If_Exists(int32u server_id, int32u seq_num) {
  retrieved_cert *cert;
  stdit it;
  stdhash *h;
  
  h = &Retrieved_PO_Cert[server_id];
  
  stdhash_find(h, &it, &seq_num);
  
  /* If there is nothing in the slot, then do not create a slot. */
  if (stdhash_is_end(h, &it))
    /* There is no slot. */
    cert = NULL;
  else cert = *((retrieved_cert**)stdhash_it_val(&it));
  
  return cert;
}

db_state_part* RECOVERY_Get_DB_State_Part(int32u block, int32u part_num) {
  db_state_part *part;
  stdit it;
  stdhash *h;

  h = &(db_state_block[block].parts);
  stdhash_find(h, &it, &part_num);

  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it)) {
    /* Allocate memory for a slot. */
	if((part = (db_state_part *) new_ref_cnt(DB_STATE_OBJ)) == NULL)
      Alarm(EXIT, "Could not allocate memory for db state part.\n");
      memset((void*)part, 0, sizeof(part));
      /* insert this cert in the hash */
      stdhash_insert(h, NULL, &part_num, &part);
  }
  else part = *((db_state_part**)stdhash_it_val(&it));

  return part;
}

db_state_part* RECOVERY_Get_DB_State_Part_If_Exists(int32u block, int32u part_num) {
  db_state_part *part;
  stdit it;
  stdhash *h;

  h = &(db_state_block[block].parts);
  stdhash_find(h, &it, &part_num);

  /* If there is nothing in the slot, then do not create a slot. */
  if (stdhash_is_end(h, &it))
    /* There is no slot. */
    part = NULL;
  else part = *((db_state_part**)stdhash_it_val(&it));

  return part;
}

void RECOVERY_Print_Digest(byte *digest) {
  int32u i;
  for(i = 0; i < DIGEST_SIZE; i++)
    Alarm(PRINT, "%02X", (int)digest[i]);
  Alarm(PRINT, "\n");
}

void RECOVERY_Cleanup() {
  UTIL_Stopwatch_Stop(&BENCH.message_validation);
  int32u i;

  // Clean up data structures
  for(i = 1; i <= NUM_SERVERS; i++)
    stdhash_empty(&Retrieved_PO_Cert[i]);
  for(i = 1; i <= DATA.STATE.num_of_blocks; i++)
    if(db_state_block[i].compromised_block == 1)
      stdhash_empty(&db_state_block[i].parts);
  stdhash_empty(&Retrieved_ORD_Cert);
}

void RECOVERY_Read_State() {
  off_t filesize, num_of_blocks;
  byte digest[DIGEST_SIZE] = "";
  char *buffer;
  int i;
  util_stopwatch time;

  fseeko(DATA.STATE.fp, 0L, SEEK_END);
  filesize = ftello(DATA.STATE.fp);
  fseeko(DATA.STATE.fp, 0L, SEEK_SET);
  num_of_blocks = ceil((double)filesize/(BLOCK_SIZE));

  buffer = (char *)malloc((BLOCK_SIZE + DIGEST_SIZE) * sizeof(char));
  UTIL_Stopwatch_Start(&time);
  for(i = 1; i <= num_of_blocks; i++) {
    fread(buffer, sizeof(char), BLOCK_SIZE, DATA.STATE.fp);
    if(strcmp((char *)digest, "") == 0)
      strcat(buffer, (char *)digest);
    OPENSSL_RSA_Make_Digest((byte *)buffer, sizeof(buffer), digest);
  }
  UTIL_Stopwatch_Stop(&time);
  memcpy(DATA.STATE.digest, digest, DIGEST_SIZE);
  free(buffer);
  Alarm(PRINT, "Digest computation complete in %.2f seconds.\n", UTIL_Stopwatch_Elapsed(&time));
}

int32u RECOVERY_Select_Server() {
  return 1 + rand() % NUM_SERVERS;
}
