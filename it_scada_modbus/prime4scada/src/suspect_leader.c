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
#include "suspect_leader.h"
#include "view_change.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
void   SUSPECT_Upon_Receiving_RTT_Ping  (signed_message *mess);
void   SUSPECT_Upon_Receiving_RTT_Pong  (signed_message *mess);
void   SUSPECT_Upon_Receiving_RTT_Measure  (signed_message *mess);
void   SUSPECT_Upon_Receiving_TAT_Measure  (signed_message *mess);
void   SUSPECT_Upon_Receiving_TAT_UB  (signed_message *mess);
void   SUSPECT_Upon_Receiving_New_Leader (signed_message *mess);
void   SUSPECT_Upon_Receiving_New_Leader_Proof (signed_message *mess);

void   SUSPECT_Ping_Periodically (int dummy, void *dummyp);
void   SUSPECT_TAT_Measure_Periodically(int dummy, void *dummyp);
void   SUSPECT_TAT_UB_Periodically(int dummy, void *dummyp);
void   SUSPECT_Suspect_Leader_Periodically(int dummy, void *dummyp);
void   SUSPECT_New_Leader_Proof_Periodically(int dummy, void *dummyp);

void SUSPECT_Dispatcher(signed_message *mess)
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
    
  case RTT_PING:
    SUSPECT_Upon_Receiving_RTT_Ping(mess);
    break;
    
  case RTT_PONG:
    SUSPECT_Upon_Receiving_RTT_Pong(mess);
    break;

  case RTT_MEASURE:
    SUSPECT_Upon_Receiving_RTT_Measure(mess);
    break;
   
  case TAT_MEASURE:
    SUSPECT_Upon_Receiving_TAT_Measure(mess);
    break;

  case TAT_UB:
    SUSPECT_Upon_Receiving_TAT_UB(mess);
    break;

  case NEW_LEADER:
    SUSPECT_Upon_Receiving_New_Leader(mess);
    break;

  case NEW_LEADER_PROOF:
    SUSPECT_Upon_Receiving_New_Leader_Proof(mess);
    break;

  default:
    INVALID_MESSAGE("SUSPECT Dispatcher");
  }
}

void SUSPECT_Initialize_Data_Structure()
{
    SUSPECT_Initialize_Upon_View_Change();
    DATA.SUS.sent_proof = 0; 
    int i;
    for (i = 1; i <= NUM_SERVERS; i++) {
	DATA.SUS.new_leader[i] = NULL;
    }
    SUSPECT_Ping_Periodically(0, NULL);
    SUSPECT_TAT_Measure_Periodically(0, NULL);
    SUSPECT_TAT_UB_Periodically(0, NULL);
    SUSPECT_Suspect_Leader_Periodically(0, NULL);
}

void SUSPECT_Initialize_Upon_View_Change(void) {
    int i;
    for (i = 1; i <= NUM_SERVERS; i++) {
	DATA.SUS.tats_if_leader[i] = 10000000.0;
	DATA.SUS.tat_leader_ubs[i] = 10000000.0;
	if (VAR.My_Server_ID == i) {
	    DATA.SUS.tats_if_leader[i] = 0;
	}
	DATA.SUS.reported_tats[i] = 0;
    }
    DATA.SUS.tat_leader = 0.0;
    DATA.SUS.tat_acceptable = 10000000.0;
    DATA.SUS.ping_seq_num = 0;
    DATA.SUS.max_tat = 0.0;
    DATA.SUS.turnaround_on = 0;
    DATA.SUS.new_leader_count = 0;
}

void SUSPECT_TAT_Measure_Periodically(int dummy, void *dummyp) {
    sp_time t;

    if (DATA.SUS.turnaround_on) {
	UTIL_Stopwatch_Stop(&DATA.SUS.turnaround_time);
	double tat = UTIL_Stopwatch_Elapsed(&DATA.SUS.turnaround_time);
	//printf("tat %f max_tat %f\n", tat, DATA.SUS.max_tat);
	if (tat > DATA.SUS.max_tat) {
	    //printf("tat higher %f\n", tat);
	    DATA.SUS.max_tat = tat;
	}
    }

    SUSPECT_Send_TAT_Measure();
    t.sec = SUSPECT_TAT_MEASURE_SEC;
    t.usec = SUSPECT_TAT_MEASURE_USEC;
    E_queue(SUSPECT_TAT_Measure_Periodically, 0, NULL, t); 
}

void SUSPECT_TAT_UB_Periodically(int dummy, void *dummyp) {
    sp_time t;

    double tats[NUM_SERVER_SLOTS];
    int i;

    for (i = 1; i <= NUM_SERVERS; i++) {
	tats[i] = DATA.SUS.tats_if_leader[i];
    }
    //printf("tat_ub_per %f %f %f %f\n", tats[1], tats[2], tats[3], tats[4]);
    qsort((void*)(tats+1), NUM_SERVERS, sizeof(double), doublecmp);

    double alpha = tats[NUM_SERVER_SLOTS-(VAR.Faults + 1)];
    //printf("alpha %f\n", alpha);

    SUSPECT_Send_TAT_UB(alpha);
    t.sec = SUSPECT_TAT_UB_SEC;
    t.usec = SUSPECT_TAT_UB_USEC;
    E_queue(SUSPECT_TAT_UB_Periodically, 0, NULL, t); 
}

void SUSPECT_Ping_Periodically (int dummy, void *dummyp) 
{
    sp_time t;

    DATA.SUS.ping_seq_num++;
    SUSPECT_Send_RTT_Ping();
    t.sec = SUSPECT_PING_SEC;
    t.usec = SUSPECT_PING_USEC;
    E_queue(SUSPECT_Ping_Periodically, 0, NULL, t);
}

void SUSPECT_New_Leader_Proof_Periodically (int dummy, void *dummyp) 
{
    sp_time t;

    if (DATA.SUS.new_leader_count <= 2*VAR.Faults || DATA.preinstall == 0) { //Stop once fully installed the view
	DATA.SUS.sent_proof = 0; 
	return;
    }

    SUSPECT_Send_New_Leader_Proof();
    t.sec = SUSPECT_LEADER_SEC;
    t.usec = SUSPECT_LEADER_USEC;
    E_queue(SUSPECT_New_Leader_Proof_Periodically, 0, NULL, t);
}


void SUSPECT_Suspect_Leader_Periodically(int dummy, void *dummyp)
{
    sp_time t;

    Alarm(DEBUG, "tat_leader %f tat_acceptable %f\n", DATA.SUS.tat_leader, DATA.SUS.tat_acceptable);
    if (DATA.SUS.tat_leader > DATA.SUS.tat_acceptable) {
	Alarm(PRINT, "Leader is suspicious\n");
	//Send New_Leader msg
	SUSPECT_Send_New_Leader();

    } else {
	Alarm(DEBUG, "Leader is not suspicious\n");
    }
    
    t.sec = SUSPECT_LEADER_SEC;
    t.usec = SUSPECT_LEADER_USEC;
    E_queue(SUSPECT_Suspect_Leader_Periodically, 0, NULL, t);
}

void SUSPECT_Send_New_Leader() {
    signed_message *new_leader;
    new_leader = SUSPECT_Construct_New_Leader();
    Alarm(DEBUG, "Add: New Leader\n");

    SIG_Add_To_Pending_Messages(new_leader, BROADCAST, UTIL_Get_Timeliness(NEW_LEADER));
    dec_ref_cnt(new_leader);
}

void SUSPECT_Send_RTT_Ping () 
{
    signed_message *ping;

    ping = SUSPECT_Construct_RTT_Ping();

    UTIL_Stopwatch_Start(&DATA.SUS.rtt);
    Alarm(DEBUG, "Add: Ping\n");
    //printf("Sending ping to all, seq # %d\n", DATA.SUS.ping_seq_num);

    SIG_Add_To_Pending_Messages(ping, BROADCAST, UTIL_Get_Timeliness(RTT_PING));
    dec_ref_cnt(ping);
}

void SUSPECT_Upon_Receiving_RTT_Ping  (signed_message *mess) 
{
    rtt_ping_message *ping = (rtt_ping_message*)(mess + 1);
    SUSPECT_Send_RTT_Pong(mess->machine_id, ping->ping_seq_num);
}

void SUSPECT_Send_RTT_Pong (int32u server_id, int32u seq_num)
{
    signed_message *pong;
    pong = SUSPECT_Construct_RTT_Pong(server_id, seq_num);
   
    int32u dest_bits = 0; 
    UTIL_Bitmap_Set(&dest_bits, server_id);

    Alarm(DEBUG, "Add: Pong\n");
    //printf ("Sending Pong to %d, %d, seq # %d\n", server_id, dest_bits, seq_num);
    SIG_Add_To_Pending_Messages(pong, dest_bits, UTIL_Get_Timeliness(RTT_PONG));
    dec_ref_cnt(pong);
}

void SUSPECT_Upon_Receiving_RTT_Pong  (signed_message *mess) 
{
    //rtt_pong_message *pong = (rtt_pong_message*)(mess + 1);
   
    UTIL_Stopwatch_Stop(&DATA.SUS.rtt);
    double rtt = UTIL_Stopwatch_Elapsed(&DATA.SUS.rtt);
    //printf("Received Pong from %d, seq # %d, RTT %f sec\n", mess->machine_id, pong->ping_seq_num, rtt);

    SUSPECT_Send_RTT_Measure(mess->machine_id, rtt);
}

void SUSPECT_Send_RTT_Measure(int32u server_id, double rtt)
{
    signed_message *measure;
    int32u dest_bits = 0;

    measure = SUSPECT_Construct_RTT_Measure(server_id, rtt);

    UTIL_Bitmap_Set(&dest_bits, server_id);

    Alarm(DEBUG, "Add: RTT Measure\n");
    SIG_Add_To_Pending_Messages(measure, dest_bits, UTIL_Get_Timeliness(RTT_MEASURE));
    dec_ref_cnt(measure);
}

void SUSPECT_Upon_Receiving_RTT_Measure  (signed_message *mess) 
{

}

void SUSPECT_Upon_Receiving_TAT_Measure  (signed_message *mess) 
{

}

void SUSPECT_Send_TAT_Measure()
{
    signed_message *measure;
    measure = SUSPECT_Construct_TAT_Measure(DATA.SUS.max_tat);

    Alarm(DEBUG, "Add: TAT Measure\n");
    SIG_Add_To_Pending_Messages(measure, BROADCAST, UTIL_Get_Timeliness(TAT_MEASURE));
    dec_ref_cnt(measure);

}

void SUSPECT_Upon_Receiving_TAT_UB  (signed_message *mess) 
{

}


void SUSPECT_Send_TAT_UB (double alpha)
{
    signed_message *measure;
    measure = SUSPECT_Construct_TAT_UB(alpha);

    Alarm(DEBUG, "Add: TAT UB\n");
    SIG_Add_To_Pending_Messages(measure, BROADCAST, UTIL_Get_Timeliness(TAT_UB));
    dec_ref_cnt(measure);
}

void   SUSPECT_Upon_Receiving_New_Leader (signed_message *mess) {
    //new_leader_signed_message* new_leader = (new_leader_signed_message*)mess;

    //Alarm(PRINT, "Received New Leader %d %d\n", DATA.SUS.sent_proof, DATA.SUS.new_leader_count);
    if (DATA.SUS.sent_proof == 0 && DATA.SUS.new_leader_count > 2*VAR.Faults) {
	DATA.SUS.sent_proof = 1;
	SUSPECT_New_Leader_Proof_Periodically(0, NULL);
	VIEW_Start_View_Change();
    }
}

void SUSPECT_Send_New_Leader_Proof() {
    signed_message *proof;
    proof = SUSPECT_Construct_New_Leader_Proof();
    Alarm(DEBUG, "Add: New Leader Proof\n");

    SIG_Add_To_Pending_Messages(proof, BROADCAST, UTIL_Get_Timeliness(NEW_LEADER_PROOF));
    dec_ref_cnt(proof);
}

void   SUSPECT_Upon_Receiving_New_Leader_Proof (signed_message *mess) {
    //Alarm(PRINT, "Received New Leader Proof\n");
    if (DATA.SUS.sent_proof == 0) {
	DATA.SUS.sent_proof = 1;
	SUSPECT_New_Leader_Proof_Periodically(0, NULL);
	VIEW_Start_View_Change();
    }
}

/* These two functions are exposed to other protocols so they can simply call the function at the proper times */

void SUSPECT_Start_Measure_TAT() {
    Alarm(DEBUG, "Start measuring turnaround time, on %d\n", DATA.SUS.turnaround_on);
    if (DATA.SUS.turnaround_on) {
	return;
    }

    UTIL_Stopwatch_Start(&DATA.SUS.turnaround_time);
    DATA.SUS.turnaround_on = 1;
}

void SUSPECT_Stop_Measure_TAT() {
    Alarm(DEBUG, "Stop measuring turnaround time, on %d\n", DATA.SUS.turnaround_on);
    if (!DATA.SUS.turnaround_on) {
	return;
    }
    UTIL_Stopwatch_Stop(&DATA.SUS.turnaround_time);
    DATA.SUS.turnaround_on = 0;
    double tat = UTIL_Stopwatch_Elapsed(&DATA.SUS.turnaround_time);

    if (tat > DATA.SUS.max_tat) {
	DATA.SUS.max_tat = tat;
    }
}

void SUSPECT_Cleanup()
{

}
