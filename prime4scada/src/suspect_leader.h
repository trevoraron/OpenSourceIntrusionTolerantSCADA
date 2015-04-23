#ifndef PRIME_SUSPECT_LEADER_H
#define PRIME_SUSPECT_LEADER_H

#include "packets.h"
#include "data_structs.h"

void SUSPECT_Dispatcher (signed_message *mess);

void SUSPECT_Initialize_Data_Structure (void);
void SUSPECT_Initialize_Upon_View_Change(void);

void SUSPECT_Send_RTT_Ping(void);
void SUSPECT_Send_RTT_Pong(int32u server_id, int32u seq_num);
void SUSPECT_Send_RTT_Measure(int32u server_id, double rtt);
void SUSPECT_Send_TAT_Measure(void);
void SUSPECT_Send_TAT_UB(double alpha);
void SUSPECT_Send_New_Leader(void);
void SUSPECT_Send_New_Leader_Proof(void);

void SUSPECT_Start_Measure_TAT(void);
void SUSPECT_Stop_Measure_TAT(void);

void SUSPECT_Cleanup(void);

#endif
