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

/* Pre Order Functions. */

#ifndef PRIME_PRE_ORDER_H
#define PRIME_PRE_ORDER_H

#include "data_structs.h"

void PRE_ORDER_Initialize_Data_Structure (void);
void PRE_ORDER_Garbage_Collect_PO_Slot(int32u server_id, int32u seq_num);

/* Dispatcher function */
void PRE_ORDER_Dispatcher (signed_message *mess);

void PRE_ORDER_Send_PO_Ack      (void);
void PRE_ORDER_Send_PO_ARU      (void);
void PRE_ORDER_Send_Proof_Matrix(void);

void PRE_ORDER_Attempt_To_Send_PO_Request(void);

bool PRE_ORDER_Latest_Proof_Sent       (void);
void PRE_ORDER_Update_Latest_Proof_Sent(void);

int32u PRE_ORDER_Proof_ARU (int32u server, po_aru_signed_message *proof);
int32u PRE_ORDER_Update_ARU(void);
int32u PRE_ORDER_Update_Cum_ARU(void);
#endif
