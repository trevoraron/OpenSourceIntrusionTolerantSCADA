#ifndef PRIME_RELIABLE_BROADCAST_H
#define PRIME_RELIABLE_BROADCAST_H

#include "packets.h"
#include "data_structs.h"

void RELIABLE_Broadcast_Reliably(signed_message *mess);

void RELIABLE_Dispatcher (signed_message *mess);

void RELIABLE_Initialize_Data_Structure (void);
void RELIABLE_Initialize_Upon_View_Change (void);

void RELIABLE_Send_RB_Init(signed_message *mess);
void RELIABLE_Send_RB_Echo(signed_message *mess);
void RELIABLE_Send_RB_Ready(signed_message *mess);

void RELIABLE_Cleanup(void);

#endif
