/*
 * Steward.
 *     
 * The contents of this file are subject to the Steward Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/byzrep/steward/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Steward are:
 *  Yair Amir, Claudiu Danilov, Danny Dolev, Jonathan Kirsch, John Lane,
 *  Cristina Nita-Rotaru, Josh Olsen, and David Zage.
 *
 * Copyright (c) 2005 - 2010 
 * The Johns Hopkins University, Purdue University, The Hebrew University.
 * All rights reserved.
 *
 */

#include "arch.h"


void TC_Read_Partial_Key( int32u server_no, int32u site_id );

void TC_Read_Public_Key();

int32u TC_Generate_Sig_Share( byte* destination, byte* hash  ); 

void TC_Initialize_Combine_Phase( int32u number );

void TC_Add_Share_To_Be_Combined( int server_no, byte *share );

void TC_Destruct_Combine_Phase( int32u number );

void TC_Combine_Shares( byte *signature_dest, byte *digest );

int32u TC_Verify_Signature( int32u site, byte *signature, byte *digest );

void TC_Generate();

