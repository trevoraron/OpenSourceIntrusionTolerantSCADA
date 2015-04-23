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

#ifndef PRIME_ERASURE_H
#define PRIME_ERASURE_H

#include "arch.h"
#include "data_structs.h"
#include "util_dll.h"
#include "def.h"
#include "recon.h"

/*----------------------Generic Erasure Encoding Interface------------------*/

/* Initialize the Erasure Encoding library.  This function should be called
 * once and should do whatever is necessary to set up the erasure encoding
 * library for use. */
void ERASURE_Initialize(void);

/* Reset the contents of the Erasure encoding data structure.  This function
 * should be called before a new encoding or decoding is to begin to reset
 * internal data structures (i.e., so the last encoding or decoding won't
 * affect the current one). */
void ERASURE_Clear(void);

/* Initialize the decoding process by passing in the length of the
 * message to be decoded, the number of message packets, and the
 * number of redundant packets. Note that the length is the only field
 * in our erasure_part structure (i.e., it is carried along with the
 * encoded part so that the decoder knows how many bytes are in the
 * final message). */
void ERASURE_Initialize_Decoding(int32u message_len, int32u message_packets,
				 int32u redundant_packets);

/* Initialize the encoding process by passing in the message to be
 * encoded, the number of message packets, and the number of redundant
 * packets.  This should store the message to be encoded into an
 * internal buffer. */
void ERASURE_Initialize_Encoding(signed_message *mess, int32u message_packets, 
				 int32u redundant_packets);

/* This function performs the actual encoding and stores all encoded parts
 * into the given buffer. */
void ERASURE_Encode(int32u *buf);

/* Sets the encoded part as part of the decoding process. It is assumed
 * that the index of the part can be determined. */
void ERASURE_Set_Encoded_Part(erasure_part *part);

/* Decodes the message from the associated set of encoded parts and
 * stores the result in mess. Returns 0 if successful and 1
 * otherwise. */
int ERASURE_Decode(signed_message *mess);

/* Returns the total length of the erasure encoded part in bytes, including
 * its index. */
int32u ERASURE_Get_Total_Part_Length(void);
/*-------------------------------------------------------------------------*/

#endif
