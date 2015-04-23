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

#ifndef PRIME_ORDER_H
#define PRIME_ORDER_H

#include "packets.h"
#include "data_structs.h"

void ORDER_Dispatcher (signed_message *mess);

/* What triggers us to call Send_One_Pre_Prepare: either the timer or
 * a PO-ARU message */
#define TIMEOUT_CALLER 1
#define MESSAGE_CALLER 2
int32u ORDER_Send_One_Pre_Prepare   (int32u caller);

void ORDER_Execute_Event(signed_message *event);
void ORDER_Execute_Commit(ord_slot *slot);

void ORDER_Initialize_Data_Structure (void);
void   ORDER_Periodically                (int dummy, void *dummyp);
void ORDER_Update_Forwarding_White_Line (void);
void ORDER_Attempt_To_Garbage_Collect_ORD_Slot (int32u seq);
void ORDER_Garbage_Collect_ORD_Slot(ord_slot *slot);

void ORDER_Attempt_To_Execute_Pending_Commits (int dummy, void *dummyp);
void ORDER_Cleanup(void);

#endif
