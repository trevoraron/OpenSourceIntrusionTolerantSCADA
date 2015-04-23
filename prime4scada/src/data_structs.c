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

/* data_structs.c: This file contains all globally defined data structures.
 * This corresponds closely to the datastructure section of the pseudocode. The
 * structures are defined in data_structs.h and the variables are defined here.
 * We also define initialization and utility functions. */

/* Globally Accessible Variables -- These should be the only global variables
 * in the program -- Note that global does not refer to "global ordering" but
 * instead to standard global variables in C */

#include <stdlib.h>
#include "data_structs.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "stopwatch.h"
#include "pre_order.h"
#include "order.h"
#include "suspect_leader.h"
#include "view_change.h"
#include "reliable_broadcast.h"
#include "signature.h"
#include "utility.h"
#include "proactive_recovery.h"
/* The globally accessible variables */

server_variables   VAR;
network_variables  NET;
server_data_struct DATA;
benchmark_struct   BENCH;
catch_up_struct    CAT;
state_data_struct  STATE;

/* Data structure initialization funtions */

void DAT_Initialize() 
{
  int32u i;
  char buf[128];
  
  /* VAR and NET get initialized elsewhere. */
  
  /* Initialize data structures */
  DATA.View    = 1;
  DATA.preinstall = 0;
  DATA.buffering_during_recovery = 0;
  DATA.execute_batch = 0;
  PRE_ORDER_Initialize_Data_Structure();
  ORDER_Initialize_Data_Structure();
  SUSPECT_Initialize_Data_Structure();
  SIG_Initialize_Data_Structure();
  RELIABLE_Initialize_Data_Structure();
  VIEW_Initialize_Data_Structure();
  Alarm(DEBUG, "Initialized PO, ORDER, and SIG data structures.\n");

  /* We need to initialize the erasure codes no matter what because
   * we use erasure-encoded reconciliation in Prime. */
  ERASURE_Initialize();

  for(i = 1; i <= NUM_CLIENTS; i++)
    DATA.PO.client_ts[i] = 0;

  BENCH.updates_executed         = 0;
  BENCH.num_po_requests_sent     = 0;
  BENCH.total_updates_requested  = 0;
  BENCH.num_po_acks_sent         = 0;
  BENCH.num_acks                 = 0;
  BENCH.num_flooded_pre_prepares = 0;
  BENCH.clock_started            = 0;

  for(i = 0; i < 21; i++) {
    BENCH.bits[i] = 0;
    BENCH.total_bits_sent[i] = 0;  
  }

  BENCH.num_signatures = 0;
  BENCH.total_signed_messages = 0;
  BENCH.max_signature_batch_size = 0;
  for(i = 0; i < LAST_MESSAGE_TYPE; i++)
    BENCH.signature_types[i] = 0;

  sprintf(buf, "state_machine_out.%d.log", VAR.My_Server_ID);
  if((BENCH.state_machine_fp = fopen(buf, "w")) == NULL) {
    Alarm(PRINT, "Could not open file %s for writing.\n", buf);
    exit(0);
  }

  /* Start recovery */
  #if RECOVERY
  DATA.recovery_in_progress = 1;
  RECOVERY_Initialize_Data_Structure();
  #endif
  Alarm(PRINT, "Initialized data structures.\n");
}
