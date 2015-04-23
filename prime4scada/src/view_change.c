#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "spu_alarm.h"
#include "spu_memory.h"
#include "order.h"
#include "data_structs.h"
#include "utility.h"
#include "util_dll.h"
#include "def.h"
#include "apply.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "dispatcher.h"
#include "signature.h"
#include "erasure.h"
#include "recon.h"
#include "view_change.h"
#include "reliable_broadcast.h"
#include "suspect_leader.h"
#include "proactive_recovery.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
void VIEW_Upon_Receiving_Report  (signed_message *mess);
void VIEW_Upon_Receiving_PC_Set  (signed_message *mess);
void VIEW_Upon_Receiving_VC_List  (signed_message *mess);
void VIEW_Upon_Receiving_VC_Partial_Sig (signed_message *mess);
void VIEW_Upon_Receiving_VC_Proof (signed_message *mess);
void VIEW_Upon_Receiving_Replay (signed_message *mess);
void VIEW_Upon_Receiving_Replay_Prepare  (signed_message *mess);
void VIEW_Upon_Receiving_Replay_Commit  (signed_message *mess);

void VIEW_Flood_Replay(signed_message *mess);
void VIEW_Execute_Replay();
void VIEW_Clear_Data_Structure();


void VIEW_Dispatcher(signed_message *mess)
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
    
  case REPORT:
    VIEW_Upon_Receiving_Report(mess);
    break;
    
  case PC_SET:
    VIEW_Upon_Receiving_PC_Set(mess);
    break;

  case VC_LIST:
    VIEW_Upon_Receiving_VC_List(mess);
    break;

  case VC_PARTIAL_SIG:
    VIEW_Upon_Receiving_VC_Partial_Sig(mess);
    break;
   
  case REPLAY_PREPARE:
    VIEW_Upon_Receiving_Replay_Prepare(mess);
    break;

  case REPLAY_COMMIT:
    VIEW_Upon_Receiving_Replay_Commit(mess);
    break;

  case VC_PROOF:
    VIEW_Upon_Receiving_VC_Proof(mess);
    break;

  case REPLAY:
    VIEW_Upon_Receiving_Replay(mess);
    break;

  default:
    INVALID_MESSAGE("VIEW Dispatcher");
  }
}

void VIEW_Initialize_Data_Structure()
{
    DATA.VIEW.replay = NULL;
    int i;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	UTIL_DLL_Initialize(&DATA.VIEW.pc_set[i]);
	DATA.VIEW.replay_prepare[i] = NULL;
	DATA.VIEW.replay_commit[i] = NULL;

    }
    UTIL_DLL_Initialize(&DATA.VIEW.my_pc_set);
    VIEW_Clear_Data_Structure();
}

void VIEW_Clear_Data_Structure() {
    if (DATA.VIEW.replay != NULL) {
	dec_ref_cnt(DATA.VIEW.replay);
	DATA.VIEW.replay = NULL;
    }
    UTIL_DLL_Clear(&DATA.VIEW.my_pc_set);
    //TODO: look over view_change data struct to see what needs to be reset..
    int i, j;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	DATA.VIEW.received_report[i] = 0;
	DATA.VIEW.received_vc_list[i] = 0;
	DATA.VIEW.sent_vc_partial_sig[i] = 0;
	UTIL_DLL_Clear(&DATA.VIEW.pc_set[i]);
	bzero(&DATA.VIEW.report[i], sizeof(report_message));

	if (DATA.VIEW.replay_prepare[i] != NULL) {
	    dec_ref_cnt(DATA.VIEW.replay_prepare[i]);
	    DATA.VIEW.replay_prepare[i] = NULL;
	}
	if (DATA.VIEW.replay_commit[i] != NULL) {
	    dec_ref_cnt(DATA.VIEW.replay_commit[i]);
	    DATA.VIEW.replay_commit[i] = NULL;
	}
	for (j = 0; j < NUM_SERVERS; ++j) {
	    DATA.VIEW.received_vc_partial_sig[i][j] = 0;
	    bzero(&DATA.VIEW.vc_partial_sig[i][j], sizeof(vc_partial_sig_message));
	}
    }

    DATA.VIEW.sent_vc_list = 0;
    DATA.VIEW.sent_replay = 0;
    DATA.VIEW.sent_prepare = 0;
    DATA.VIEW.complete_state = 0;
    DATA.VIEW.sent_commit = 0;
    DATA.VIEW.commit_ready = 0;
    DATA.VIEW.prepare_ready = 0;
    DATA.VIEW.highest_server_id = 0;
    DATA.VIEW.numSeq = 0;
    DATA.VIEW.curSeq = 0;
    DATA.VIEW.executeTo = 0;
}


void VIEW_Start_View_Change() {
    if(DATA.recovery_in_progress == 1 || DATA.buffering_during_recovery == 1) {
      DATA.preinstall = 0;
      return;
    }
    //This is where I set any values that need to be changed
    //upon a view change

    Alarm(DEBUG, "Start view change\n");
    
    SUSPECT_Initialize_Upon_View_Change();
    RELIABLE_Initialize_Upon_View_Change();

    VIEW_Clear_Data_Structure(); 

    /* This bit of code finds all of the updates that have a
     * prepare-certificate but have not been executed, then forms a pc-set 
     * message which we will send later */

    stdit it;
    stdhash *h;
    ord_slot *slot;
    h = &DATA.ORD.History;
    int i;

    stdhash_begin(h, &it);
    while (!stdhash_is_end(h, &it)) {
	char cert[PRIME_MAX_PACKET_SIZE];
	int offset = 0;
	slot = *((ord_slot**)stdhash_it_val(&it));
	if (slot->sent_commit && !slot->executed) {

	    Alarm(DEBUG, "SLOT %d execute %d\n", slot->seq_num, slot->execute_commit);
	    memcpy(cert, slot->pre_prepare, UTIL_Message_Size(slot->pre_prepare));
	    offset += UTIL_Message_Size(slot->pre_prepare);
	    //Alarm(DEBUG, "size of pre-prepare %d, type %d\n", UTIL_Message_Size(slot->pre_prepare), slot->pre_prepare->type);

	    int count = 0;
	    for (i = 1; i <= NUM_SERVERS; ++i) {
		if (count < 2*VAR.Faults && slot->prepare_certificate.prepare[i]) {
		    memcpy(cert + offset, slot->prepare_certificate.prepare[i], UTIL_Message_Size(slot->prepare_certificate.prepare[i]));
		    offset += UTIL_Message_Size(slot->prepare_certificate.prepare[i]);
		    //Alarm(DEBUG, "size of prepare %d\n", UTIL_Message_Size(slot->prepare_certificate.prepare[i]));
		    count++;
		}
	    }
	    //Alarm(DEBUG, "size of prepare cert %d\n", offset);
	    UTIL_DLL_Add_Data(&DATA.VIEW.my_pc_set, VIEW_Construct_PC_Set(cert, offset));
	    DATA.VIEW.numSeq++;

	}
	stdhash_it_next(&it);
    }
    stdhash_begin(h, &DATA.VIEW.seq_it);

    /* Send the report message which indicates (among other things) how many pc-set messages you are going to send */

    VIEW_Send_Report();
    DATA.VIEW.executeTo = DATA.ORD.ARU;
}

void VIEW_Send_Report() {
    signed_message *report;
    report = VIEW_Construct_Report();

    Alarm(DEBUG, "Add: Report\n");

    RELIABLE_Broadcast_Reliably(report);
    dec_ref_cnt(report);
}

void VIEW_Send_PC_Set() {

    signed_message *pc_set = UTIL_DLL_Front_Message(&DATA.VIEW.my_pc_set);
    DATA.VIEW.curSeq++;
    Alarm(DEBUG, "Add: PC_Set\n");

    RELIABLE_Broadcast_Reliably(pc_set);
    dec_ref_cnt(pc_set);
    UTIL_DLL_Pop_Front(&DATA.VIEW.my_pc_set);
}

void VIEW_Send_VC_List() {
    signed_message *vc_list;
    vc_list = VIEW_Construct_VC_List();
    Alarm(DEBUG, "Add: VC_List\n");
    SIG_Add_To_Pending_Messages(vc_list, BROADCAST, UTIL_Get_Timeliness(VC_LIST));
    dec_ref_cnt(vc_list);
}

void VIEW_Send_VC_Partial_Sig(int32u ids) {
    signed_message *vc_partial_sig;
    vc_partial_sig = VIEW_Construct_VC_Partial_Sig(ids);
    Alarm(DEBUG, "Add: VC_Partial_Sig\n");
    SIG_Add_To_Pending_Messages(vc_partial_sig, BROADCAST, UTIL_Get_Timeliness(VC_PARTIAL_SIG));
    dec_ref_cnt(vc_partial_sig);
}

void VIEW_Send_VC_Proof(int32u view, int32u ids, int32u startSeq, byte *sig) {
    signed_message *vc_proof;
    vc_proof = VIEW_Construct_VC_Proof(view, ids, startSeq, sig);
    Alarm(DEBUG, "Add: VC_Proof\n");
    SUSPECT_Start_Measure_TAT();
    SIG_Add_To_Pending_Messages(vc_proof, BROADCAST, UTIL_Get_Timeliness(VC_PROOF));
    dec_ref_cnt(vc_proof);
}

void VIEW_Send_Replay(vc_proof_message *proof) {
    signed_message *replay;
    replay = VIEW_Construct_Replay(proof);
    Alarm(DEBUG, "Add: Replay\n");
    
    SIG_Add_To_Pending_Messages(replay, BROADCAST, UTIL_Get_Timeliness(REPLAY));
    dec_ref_cnt(replay);
}

void VIEW_Send_Replay_Prepare() {
    signed_message *replay;
    replay = VIEW_Construct_Replay_Prepare();
    Alarm(DEBUG, "Add: Replay Prepare\n");
    
    SIG_Add_To_Pending_Messages(replay, BROADCAST, UTIL_Get_Timeliness(REPLAY_PREPARE));
    dec_ref_cnt(replay);
}

void VIEW_Send_Replay_Commit() {
    signed_message *replay;
    replay = VIEW_Construct_Replay_Commit();
    Alarm(DEBUG, "Add: Replay Commit\n");
    
    SIG_Add_To_Pending_Messages(replay, BROADCAST, UTIL_Get_Timeliness(REPLAY_COMMIT));
    dec_ref_cnt(replay);
}

void   VIEW_Upon_Receiving_Report  (signed_message *mess) {
    Alarm(DEBUG, "Received Report\n");
    report_message *report = (report_message*)(mess+1);
    Alarm(DEBUG, "machine %d execARU %d size %d %d\n", mess->machine_id, report->execARU, report->pc_set_size, DATA.VIEW.report[mess->machine_id].pc_set_size);

    if (mess->machine_id == VAR.My_Server_ID && DATA.VIEW.curSeq < DATA.VIEW.numSeq) {
	VIEW_Send_PC_Set();
    }
    VIEW_Check_Complete_State();
}

void   VIEW_Upon_Receiving_PC_Set  (signed_message *mess) {

    Alarm(DEBUG, "received pc_set from %d\n", mess->machine_id);
    if (mess->machine_id == VAR.My_Server_ID && DATA.VIEW.curSeq < DATA.VIEW.numSeq) {
	VIEW_Send_PC_Set();
    }
    //TODO: ARU may not yet be up-to-date even though we get all state necessary, so might need some sort of periodic checking or callback to make sure vc_list is sent
    //I did add callback to Execute_Commit, check to make sure it works...
    VIEW_Check_Complete_State();
}

/* This is a call-back function that needs to be called from other places and ensures we only move forward in the view change protocol when we have the necessary state */

void VIEW_Check_Complete_State() {
    int32u i;

    /* who do we have complete state for? */
    for (i = 1; i <= NUM_SERVERS; ++i) {
	if (DATA.VIEW.received_report[i] && !UTIL_Bitmap_Is_Set(&DATA.VIEW.complete_state, i)) {
	    report_message *report = &DATA.VIEW.report[i];
	    Alarm(DEBUG, "state comparison node %d: %d %d %d %d\n", i, report->pc_set_size, DATA.VIEW.pc_set[i].length, DATA.ORD.ARU, report->execARU);
	    if (report->pc_set_size == DATA.VIEW.pc_set[i].length && DATA.ORD.ARU >= report->execARU) {
		Alarm(DEBUG, "Complete state for %d\n", i);
		UTIL_Bitmap_Set(&DATA.VIEW.complete_state, i);
	    }
	}
    }

    Alarm(DEBUG, "check complete state\n");
    if (DATA.VIEW.complete_state > 0 && UTIL_Bitmap_Num_Bits_Set(&DATA.VIEW.complete_state) >= 2*VAR.Faults+1) {
	Alarm(DEBUG, "has complete state for 2f+1\n");
	if (!DATA.VIEW.sent_vc_list) {
	    DATA.VIEW.sent_vc_list = 1;
	    VIEW_Send_VC_List();
	}
	//look at each servers sent vc_list
	for (i = 1; i <= NUM_SERVERS; ++i) {
	    Alarm(DEBUG, "received %d vc_list %d sent_partial %d\n", i, DATA.VIEW.received_vc_list[i], DATA.VIEW.sent_vc_partial_sig[i]);
	    if (DATA.VIEW.received_vc_list[i] && !DATA.VIEW.sent_vc_partial_sig[i]) {
		int j;
		int count = 0;
		//see if you have completed state for same servers
		Alarm(DEBUG, "node %d had state for ", i);
		for (j = 1; j <= NUM_SERVERS; ++j) {
		    if (UTIL_Bitmap_Is_Set(&DATA.VIEW.vc_list[i].complete_state, j)) {
			Alarm(DEBUG, "%d ", j);
			if (UTIL_Bitmap_Is_Set(&DATA.VIEW.complete_state, j)) { 
			    Alarm(DEBUG, " (so do i) ");
			    count++;
			} else {
			    break;
			}
		    }

		}
		Alarm(DEBUG, "j %d count %d\n", j, count);
		if (j > NUM_SERVERS && count >= 2*VAR.Faults+1) {
		    DATA.VIEW.sent_vc_partial_sig[i] = 1;
		    VIEW_Send_VC_Partial_Sig(DATA.VIEW.vc_list[i].complete_state);
		    Alarm(DEBUG, "sent partial sig %d\n", DATA.VIEW.sent_vc_partial_sig[1]);

		}
	    }
	}
	if (!UTIL_I_Am_Leader() && DATA.VIEW.sent_replay && !DATA.VIEW.sent_prepare) {
	    DATA.VIEW.sent_prepare = 1;
	    VIEW_Send_Replay_Prepare();
	}

	if (DATA.VIEW.prepare_ready && !DATA.VIEW.sent_commit) {
	    DATA.VIEW.sent_commit = 1;
	    VIEW_Send_Replay_Commit();
	}
	if (DATA.preinstall && DATA.VIEW.highest_server_id > 0 && UTIL_Bitmap_Is_Set(&DATA.VIEW.complete_state, DATA.VIEW.highest_server_id)) {
	    VIEW_Execute_Replay();
	}
    } 
}


void   VIEW_Upon_Receiving_VC_List  (signed_message *mess) {
    Alarm(DEBUG, "Received VC_List %d\n", DATA.VIEW.sent_vc_partial_sig[1]);
    VIEW_Check_Complete_State();
}

void   VIEW_Upon_Receiving_VC_Partial_Sig  (signed_message *mess) {
    Alarm(DEBUG, "Received VC_Partial_Sig %d\n", DATA.VIEW.sent_vc_partial_sig[1]);
    vc_partial_sig_message *partial = (vc_partial_sig_message*)(mess+1);
    int32u count = 1;
    int i, j;

    int32u gotShare[NUM_SERVER_SLOTS];
    for (i = 1; i <= NUM_SERVERS; ++i) {
	gotShare[i] = 0;
    }
    byte shares[NUM_SERVER_SLOTS][SIGNATURE_SIZE];

    gotShare[mess->machine_id] = 1;
    memcpy(shares[mess->machine_id], partial->thresh_sig, SIGNATURE_SIZE);

    for (i = 1; i <= NUM_SERVERS; ++i) {
	if (i == mess->machine_id) {
	    continue;
	}
	for (j = 0; j < NUM_SERVERS; ++j) {
	    if (DATA.VIEW.received_vc_partial_sig[i][j] && partial->ids == DATA.VIEW.vc_partial_sig[i][j].ids && partial->startSeq == DATA.VIEW.vc_partial_sig[i][j].startSeq) {
		gotShare[i] = 1;
		memcpy(shares[i], DATA.VIEW.vc_partial_sig[i][j].thresh_sig, SIGNATURE_SIZE);
		count++;
		break;
	    }
	}
    }
    Alarm(DEBUG, "So far got %d partial-sigs\n", count);
    if (count >= 2*VAR.Faults+1) {
	TC_Initialize_Combine_Phase(NUM_SERVERS+1);
	for (i = 1; i <= NUM_SERVERS; i++) {
	    if (gotShare[i]) {
		TC_Add_Share_To_Be_Combined(i, shares[i]);
	    }
	}
	byte digest[DIGEST_SIZE];
	byte sig[SIGNATURE_SIZE];
	OPENSSL_RSA_Make_Digest( 
	    partial, 
	    3*sizeof(int32u),
	    digest );
	TC_Combine_Shares(sig, digest);
	TC_Destruct_Combine_Phase(NUM_SERVERS+1);

	if (!TC_Verify_Signature(1, sig, digest)) {
	    Alarm(DEBUG, "combined sig did not verify\n");
	    return;
	}

	VIEW_Send_VC_Proof(partial->view, partial->ids, partial->startSeq, sig);
    }

}

void VIEW_Upon_Receiving_VC_Proof (signed_message *mess) {
    Alarm(DEBUG, "Received VC Proof\n");
    if (UTIL_I_Am_Leader() && !DATA.VIEW.sent_replay) {
	DATA.VIEW.sent_replay = 1;
	vc_proof_message *proof = (vc_proof_message*)(mess+1);
	VIEW_Send_Replay(proof);
    }
}

void VIEW_Upon_Receiving_Replay (signed_message *mess) {
    Alarm(DEBUG, "Received Replay\n");
    SUSPECT_Stop_Measure_TAT();

    if (!UTIL_I_Am_Leader() && !DATA.VIEW.sent_replay) {
	DATA.VIEW.sent_replay = 1;
	VIEW_Flood_Replay(mess);
	VIEW_Check_Complete_State();
    }
}

/* took this and adapted from the flood_preprepare function */

void VIEW_Flood_Replay(signed_message *mess)
{

  if(!UTIL_I_Am_Leader()) {
#if THROTTLE_OUTGOING_MESSAGES
    int32u dest_bits, i;
    /* Send it to all but the leader and myself */
    dest_bits = 0;
    for(i = 1; i <= NUM_SERVERS; i++) {
      if(i == UTIL_Leader() || i == VAR.My_Server_ID)
	continue;
      UTIL_Bitmap_Set(&dest_bits, i);
    }
    /* Note: Can't just get the traffic class from UTIL_Get_Timeliness 
     * because we need to distinguish flooded Pre-Prepares from regular
     * Pre-Prepares. */
    NET_Add_To_Pending_Messages(mess, dest_bits, BOUNDED_TRAFFIC_CLASS);
#else
    UTIL_Broadcast(mess);
#endif
  }
}


void   VIEW_Upon_Receiving_Replay_Prepare  (signed_message *mess) {
    Alarm(DEBUG, "Received Replay Prepare\n");
    VIEW_Check_Complete_State();
}

void   VIEW_Upon_Receiving_Replay_Commit  (signed_message *mess) {
    Alarm(DEBUG, "Received Replay Commit %d %d\n", DATA.VIEW.commit_ready, DATA.preinstall);
    if (DATA.VIEW.commit_ready && DATA.preinstall) {

	//have to execute based on the server that sent the highest sequence number and is in the proof, right?
	Alarm(DEBUG, "replay commit 1 %d\n", DATA.VIEW.replay);
	replay_message *replay = (replay_message*)(DATA.VIEW.replay+1);
        if(DATA.VIEW.replay == NULL)
          return;
 
	DATA.VIEW.highest_server_id = VAR.My_Server_ID;
	int i;
	for (i = 1; i <= NUM_SERVERS; ++i) {
	    if (UTIL_Bitmap_Is_Set(&replay->proof.ids, i)) {
		Alarm(DEBUG, "server %d is set in replay\n", i);
		if (replay->proof.startSeq == DATA.VIEW.report[i].execARU + DATA.VIEW.report[i].pc_set_size + 1) {
		    DATA.VIEW.highest_server_id = i;
		}
	    }
	}

	//and I have this state...
	if (DATA.preinstall && UTIL_Bitmap_Is_Set(&DATA.VIEW.complete_state, DATA.VIEW.highest_server_id)) {
	    VIEW_Execute_Replay();
	    //Otherwise will wait until Check_Complete_State() calls it
	}
    }
    Alarm(DEBUG, "done with receiving replay commit\n");
}

void VIEW_Execute_Replay() {
    assert(DATA.preinstall == 1);
    DATA.preinstall = 0;
    Alarm(DEBUG, "Executing server %d's pc_set\n", DATA.VIEW.highest_server_id); 
    replay_message *replay = (replay_message*)(DATA.VIEW.replay+1);
    signed_message *pc_set;
    pc_set_message *pc_set_specific;
    signed_message *pre_prepare;
    pre_prepare_message *pre_prepare_specific;
    po_aru_signed_message *po_aru;
    signed_message *mess;
    int32u aru, size, count = 0;
    ord_slot *slot;

    Alarm(DEBUG, "ARU %d startSeq %d\n", DATA.ORD.ARU, replay->proof.startSeq);
    for (aru = DATA.ORD.ARU+1; aru < replay->proof.startSeq; aru++) {
	if (!UTIL_DLL_Is_Empty(&DATA.VIEW.pc_set[DATA.VIEW.highest_server_id])) {
	    pc_set = UTIL_DLL_Front_Message(&DATA.VIEW.pc_set[DATA.VIEW.highest_server_id]);
	    pc_set_specific = (pc_set_message*)(pc_set+1);
	    pre_prepare = (signed_message*)(pc_set_specific+1);
	    pre_prepare_specific = (pre_prepare_message*)(pre_prepare+1);
	    po_aru = (po_aru_signed_message*)(pre_prepare_specific+1);
            //to execute correctly, and to make sure that we can continue to
	    // execute after the view change, I have to set up the ord_slots correctly
	    // and then call ORDER_Execute_Commit(ord_slot *o_slot);
	    slot = UTIL_Get_ORD_Slot(aru);
	    slot->prepare_certificate.pre_prepare.seq_num = aru;
	    slot->prepare_certificate.pre_prepare.view = pre_prepare_specific->view;
            slot->complete_pre_prepare.seq_num = aru;
            slot->complete_pre_prepare.view    = pre_prepare_specific->view;

            // copy the prepare certificate in the slot
            size = UTIL_Message_Size(pre_prepare);
            mess = (signed_message *)((char *)pre_prepare + size);
            while(count < 2 * VAR.Faults) {
              size = UTIL_Message_Size(mess);
              /* TODO better: we are leaking memory here!
               * We should free the memory used to store prepare messages during regular execution
               * before allocating new memory for prepare messages in PC_SET
               */ 
              /* if(slot->prepare_certificate.prepare[mess->machine_id] != NULL)
		free(slot->prepare_certificate.prepare[mess->machine_id]); */

	      slot->prepare_certificate.prepare[mess->machine_id] = malloc(size);
              memcpy((char*)slot->prepare_certificate.prepare[mess->machine_id], (char*)mess, size);
              /* end */
              mess = (signed_message *)((char *)mess + size);
              count++;
            }

	    slot->prepare_certificate_ready = 1;
	    slot->collected_all_parts = 1;
	    //This won't work if we don't have all the PO_Requests reflected in pre-prepare...
	    //  how do we know that this will work then?
	    Alarm(PRINT, "Executing %d in pc_set\n", aru);
	    ORDER_Execute_Commit(slot);
	    assert(DATA.ORD.ARU == aru);
	    Alarm(DEBUG, "PopFront...");
	    UTIL_DLL_Pop_Front(&DATA.VIEW.pc_set[DATA.VIEW.highest_server_id]);
	    Alarm(DEBUG, "done\n");

	}
    }

    //clear any ord_slots that have a bigger seq_num
    stdit it;
    stdhash *h;
    h = &DATA.ORD.History;

    stdhash_begin(h, &it);
    while (!stdhash_is_end(h, &it)) {
	slot = *((ord_slot**)stdhash_it_val(&it));
	if (slot->seq_num > DATA.ORD.ARU) {
	    Alarm(DEBUG, "SLOT %d getting rid of it...\n", slot->seq_num);
	    ORDER_Garbage_Collect_ORD_Slot(slot);
	    //TODO: Do I need to do this? Just to be safe I am...
	    stdhash_begin(h, &it);
	    continue;
	}
	stdhash_it_next(&it);
    }

    VIEW_Clear_Data_Structure();

    if (UTIL_I_Am_Leader()) {
	Alarm(DEBUG, "I am new leader, starting at %d next is %d\n", DATA.ORD.ARU, replay->proof.startSeq);
	//Resetting this really does seem to be necessary...
	//TODO: this *might* causes a NOP to be executed, need to check if that is the case...
	slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
	if (slot != NULL) {
	    int i;
	    for (i = 1; i <= NUM_SERVERS; i++) {
		DATA.PO.max_num_sent_in_proof[i] = PRE_ORDER_Proof_ARU(i, slot->prepare_certificate.pre_prepare.cum_acks);
	    }
	}
	//set value for ordering pre-prepares
	DATA.ORD.seq = replay->proof.startSeq;
	ORDER_Periodically(0, NULL);
    }
}


void VIEW_Cleanup()
{

}
