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

#ifndef PRIME_UTIL_DLL_H
#define PRIME_UTIL_DLL_H

#include "arch.h"
#include "stopwatch.h"

typedef struct dummy_dll_node_struct {
  void *data;
  int32u extra[2]; /* generic integers */
  void *next;
  util_stopwatch sw;
} dll_node_struct;

typedef struct dummy_dll_struct {
  dll_node_struct *begin;
  dll_node_struct *current_position;
  dll_node_struct *end;
  int32u length;
} dll_struct;

void UTIL_DLL_Initialize(dll_struct *dll);

void UTIL_DLL_Clear( dll_struct *dll ); 

void UTIL_DLL_Next( dll_struct *dll );

int32u UTIL_DLL_At_End( dll_struct *dll ); 

void UTIL_DLL_Set_Begin( dll_struct *dll );

void* UTIL_DLL_Get_Signed_Message( dll_struct *dll ); 

void UTIL_DLL_Add_Data( dll_struct *dll, void *data ); 
void UTIL_DLL_Add_Data_To_Front(dll_struct *dll, void *data); 

int32u UTIL_DLL_Is_Empty( dll_struct *dll ); 

void* UTIL_DLL_Front_Message( dll_struct *dll ); 

void UTIL_DLL_Pop_Front( dll_struct *dll ); 

void UTIL_DLL_Set_Last_Extra( dll_struct *dll, int32u index, int32u val ); 

int32u UTIL_DLL_Front_Extra( dll_struct *dll, int32u index ); 

double UTIL_DLL_Elapsed_Front( dll_struct *dll );

#endif
