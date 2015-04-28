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

/* Utility functions to access data structures and do other commonly
 * performed tasks. */

#ifndef PRIME_UTILITY_H
#define PRIME_UTILITY_H

#include "spu_events.h"
#include "data_structs.h"
#include "stopwatch.h"
#include "erasure.h"
#include "recon.h"
#include "packets.h"

/* Integer comparison function for quicksort */
int intcmp(const void *n1, const void *n2);

int doublecmp (const void *n1, const void *n2);

/* Returns the number of bytes in a signed message, including the Merkle
 * tree digest bytes that are appended. */
int32u UTIL_Message_Size(signed_message *m);

/* Returns the traffic class (timeliness) of a message.  Currently the
 * only options are BOUNDED and TIMELY. */
int32u UTIL_Get_Timeliness(int32u type);

/* Writes the client_id and timestamp of the executed update to file */
void UTIL_State_Machine_Output(signed_update_message *u);

/* Returns a string for given message type */
char *UTIL_Type_To_String(int32u type);

/* Adds a signed message of traffic class timeliness to the
 * pending_messages data structure.  The destinations are those bits
 * set in dest_bits, or everyone if dest_bits == BROADCAST == 0.  Note
 * that this is only used when outgoing messages are throttled (i.e.,
 * the THROTTLE_OUTGOING_MESSAGES flag is set in def.h */
int32u NET_Add_To_Pending_Messages(signed_message *mess, int32u dest_bits,
				   int32u timeliness);

/* Network configuration functions */
void  UTIL_Load_Addresses               (void);
void  UTIL_Test_Server_Address_Functions(void); 
int32 UTIL_Get_Server_Address           (int32u server); 
int32 UTIL_Get_Server_Spines_Address    (int32u server); 

/* Leader identification functions */
int32u UTIL_I_Am_Leader(void);
int32u UTIL_Leader     (void); 

/* Attack functions */
int32u UTIL_I_Am_Faulty(void);

/* Stopwatch functions */
void   UTIL_Stopwatch_Start  (util_stopwatch *stopwatch); 
void   UTIL_Stopwatch_Stop   (util_stopwatch *stopwatch); 
double UTIL_Stopwatch_Elapsed(util_stopwatch *stopwatch);
void   UTIL_Stopwatch_Stop_Print_Start(util_stopwatch *stopwatch); 
void   UTIL_Print_Time(void);

/* Bitmap functions */
void   UTIL_Bitmap_Set   (int32u *bm, int32u i);
void   UTIL_Bitmap_Clear (int32u *bm, int32u i);
int32u UTIL_Bitmap_Is_Set(int32u *bm, int32u i);
int32u UTIL_Bitmap_Num_Bits_Set(int32u *bm);

/* Memory allocation functions */
net_struct *UTIL_New_Net_Struct(void);
erasure_node *UTIL_New_Erasure_Node(int32u dest_bits, int32u type, 
				    int32u part_len, int32u mess_len);
erasure_part_obj *UTIL_New_Erasure_Part_Obj(void);
signed_message* UTIL_New_Signed_Message(void);

/* Slot get() functions.  The regular variant will allocate memory for
 * a new slot if no slot exists.  The "if exists" variant will not
 * allocate memory and will return NULL if no slot exists. */
po_slot    *UTIL_Get_PO_Slot             (int32u server_id, int32u seq_num);
po_slot    *UTIL_Get_PO_Slot_If_Exists   (int32u server_id, int32u seq_num);
ord_slot   *UTIL_Get_ORD_Slot            (int32u seq_num);
ord_slot   *UTIL_Get_ORD_Slot_If_Exists  (int32u seq_num);
recon_slot *UTIL_Get_Recon_Slot          (int32u originator, int32u seq_num);
recon_slot *UTIL_Get_Recon_Slot_If_Exists(int32u originator, int32u seq_num);
void      UTIL_Mark_ORD_Slot_As_Pending      (int32u gseq, ord_slot *slot);
ord_slot *UTIL_Get_Pending_ORD_Slot_If_Exists(int32u gseq);

/* Message sending functions */
void UTIL_Send_To_Server(signed_message *mess, int32u server_id); 
void UTIL_Broadcast     (signed_message *mess); 

/* Crypto functions */
void UTIL_RSA_Sign_Message(signed_message *mess);

/* Client handling functions */
void UTIL_Respond_To_Client(int32u machine_id, int32u time_stamp, byte content[UPDATE_SIZE]);
void UTIL_Write_Client_Response(signed_message *mess);
#endif
