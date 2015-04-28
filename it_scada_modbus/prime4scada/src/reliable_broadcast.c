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
#include "reliable_broadcast.h"
#include "validate.h"
#include "objects.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
void   RELIABLE_Upon_Receiving_RB_Init  (signed_message *mess);
void   RELIABLE_Upon_Receiving_RB_Echo  (signed_message *mess);
void   RELIABLE_Upon_Receiving_RB_Ready  (signed_message *mess);
void   RELIABLE_Deliver(signed_message *mess, int32u num_bytes);

void RELIABLE_Dispatcher(signed_message *mess)
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
    
  case RB_INIT:
    RELIABLE_Upon_Receiving_RB_Init(mess);
    break;
    
  case RB_ECHO:
    RELIABLE_Upon_Receiving_RB_Echo(mess);
    break;

  case RB_READY:
    RELIABLE_Upon_Receiving_RB_Ready(mess);
    break;
   
  default:
    INVALID_MESSAGE("RELIABLE Dispatcher");
  }
}

void RELIABLE_Initialize_Data_Structure()
{

    RELIABLE_Initialize_Upon_View_Change();

}

void RELIABLE_Initialize_Upon_View_Change()
{
    int i, j;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	DATA.REL.seq_num[i] = 0;
	DATA.REL.rb_step[i] = 0;
    }
    DATA.REL.sent_message = 0;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	for (j = 1; j <= NUM_SERVERS; ++j) { 
	    DATA.REL.rb_echo[i][j] = 0;
	    DATA.REL.rb_ready[i][j] = 0;
	}
    }
}

void RELIABLE_Broadcast_Reliably(signed_message *mess) {
    if (DATA.REL.sent_message == 1) {
	Alarm(DEBUG, "Trying to send multiple reliable broadcast messages at once\n");
	assert(!DATA.REL.sent_message);
    }
    DATA.REL.sent_message = 1;

    //tag message
    reliable_broadcast_tag *rb_tag = (reliable_broadcast_tag*)(mess+1);
    rb_tag->machine_id = VAR.My_Server_ID;
    rb_tag->seq_num = DATA.REL.seq_num[VAR.My_Server_ID];
    rb_tag->view = DATA.View;

    /* I don't use the merkle tree stuff here because there's no easy way to do that and then stick the message into a reliable broadcast message */
    //sign and send
    UTIL_RSA_Sign_Message(mess);
    Alarm(DEBUG, "Reliable broadcast of %d type\n", mess->type);
    RELIABLE_Send_RB_Init(mess);
}

void RELIABLE_Send_RB_Init(signed_message *mess) {
    signed_message *init;
    init = RELIABLE_Construct_RB_Init(mess);
    Alarm(DEBUG, "Add: RB_INIT inner message %d\n", mess->type);
    SIG_Add_To_Pending_Messages(init, BROADCAST, UTIL_Get_Timeliness(RB_INIT));
    dec_ref_cnt(init);

}

void RELIABLE_Send_RB_Echo(signed_message *mess) {
    signed_message *echo;
    echo = RELIABLE_Construct_RB_Echo(mess);
    Alarm(DEBUG, "Add: RB_ECHO inner message %d\n", mess->type);
    SIG_Add_To_Pending_Messages(echo, BROADCAST, UTIL_Get_Timeliness(RB_ECHO));
    dec_ref_cnt(echo);
}

void RELIABLE_Send_RB_Ready(signed_message *mess) {
    signed_message *ready;
    ready = RELIABLE_Construct_RB_Ready(mess);
    Alarm(DEBUG, "Add: RB_READY inner message %d\n", mess->type);
    SIG_Add_To_Pending_Messages(ready, BROADCAST, UTIL_Get_Timeliness(RB_READY));
    dec_ref_cnt(ready);
}

void RELIABLE_Upon_Receiving_RB_Init  (signed_message *mess) {
    Alarm(DEBUG, "Received RB_Init\n");
    inc_ref_cnt(mess);
    signed_message *payload = (signed_message*)(mess+1);
    RELIABLE_Send_RB_Echo(payload);
    DATA.REL.rb_step[payload->machine_id] = 2;
    dec_ref_cnt(mess);
}

void RELIABLE_Upon_Receiving_RB_Echo  (signed_message *mess) {
    Alarm(DEBUG, "Received RB_Echo\n");
    inc_ref_cnt(mess);
    signed_message *payload = (signed_message*)(mess+1);

    int32u echo_count = 0;
    int i;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	echo_count += DATA.REL.rb_echo[payload->machine_id][i];
    }

    if (echo_count == (NUM_SERVERS + VAR.Faults)/2) {
	if (DATA.REL.rb_step[payload->machine_id] == 1) {
	    RELIABLE_Send_RB_Echo(payload);
	    DATA.REL.rb_step[payload->machine_id] = 2;
	}
	if (DATA.REL.rb_step[payload->machine_id] == 2) {
	    RELIABLE_Send_RB_Ready(payload);
	    DATA.REL.rb_step[payload->machine_id] = 3;
	}
    }
    dec_ref_cnt(mess);

}

void RELIABLE_Upon_Receiving_RB_Ready  (signed_message *mess) {
    Alarm(DEBUG, "Received RB_Ready\n");
    inc_ref_cnt(mess);
    signed_message *payload = (signed_message*)(mess+1);

    int32u ready_count = 0;
    int i;
    for (i = 1; i <= NUM_SERVERS; ++i) {
	ready_count += DATA.REL.rb_ready[payload->machine_id][i];
    }

    if (ready_count == VAR.Faults + 1) {
	if (DATA.REL.rb_step[payload->machine_id] == 1) {
	    RELIABLE_Send_RB_Echo(payload);
	    DATA.REL.rb_step[payload->machine_id] = 2;
	}
	if (DATA.REL.rb_step[payload->machine_id] == 2) {
	    RELIABLE_Send_RB_Ready(payload);
	    DATA.REL.rb_step[payload->machine_id] = 3;
	}
    }
    if (ready_count == 2*VAR.Faults + 1 && DATA.REL.rb_step[payload->machine_id] == 3) {
	//deliver message
	RELIABLE_Deliver(payload, mess->len);
    }
    dec_ref_cnt(mess);
}

void RELIABLE_Deliver(signed_message *payload, int32u num_bytes) {
    signed_message *mess = new_ref_cnt(PACK_BODY_OBJ);
    if (mess == NULL) {
	Alarm(EXIT, "Reliable_Deliver: could not allocate space for message\n");
    }

    if (num_bytes > PRIME_MAX_PACKET_SIZE) {
	dec_ref_cnt(mess);
	return;
    }

    memcpy(mess, payload, num_bytes);
    
    Alarm(DEBUG, "Reliable broadcast deliver of %d type\n", mess->type);
    if(!VAL_Validate_Message(mess, num_bytes)) {
	dec_ref_cnt(mess);
	return;
    }
    if (VAR.My_Server_ID == mess->machine_id) {
	DATA.REL.seq_num[VAR.My_Server_ID]++;
	DATA.REL.sent_message = 0;
    }    
    APPLY_Message_To_Data_Structs(mess);
    DIS_Dispatch_Message(mess);
    dec_ref_cnt(mess);
}


void RELIABLE_Cleanup()
{

}


