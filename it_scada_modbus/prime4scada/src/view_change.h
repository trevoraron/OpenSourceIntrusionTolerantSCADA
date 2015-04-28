#ifndef PRIME_VIEW_CHANGE_H
#define PRIME_VIEW_CHANGE_H

#include "packets.h"
#include "data_structs.h"

void VIEW_Start_View_Change(void);

void VIEW_Dispatcher (signed_message *mess);

void VIEW_Initialize_Data_Structure (void);

void VIEW_Send_Report(void);
void VIEW_Send_PC_Set(void);
void VIEW_Send_VC_List(void);
void VIEW_Send_VC_Partial_Sig(int32u ids);
void VIEW_Send_VC_Proof(int32u view, int32u ids, int32u startSeq, byte *sig);
void VIEW_Send_Replay(vc_proof_message *proof);
void VIEW_Send_Replay_Prepare(void);
void VIEW_Send_Replay_Commit(void);

void   VIEW_Check_Complete_State();

void VIEW_Cleanup(void);

#endif
