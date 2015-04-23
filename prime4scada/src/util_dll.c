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

#include <stdlib.h>
#include "util_dll.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "data_structs.h"
#include "objects.h"
#include "utility.h"

/* DLL funtions */

void UTIL_DLL_Clear( dll_struct *dll ) {
  dll_node_struct *next;
  dll_node_struct *current;
  next = dll->begin;
  while ( next != NULL ) {
    current = next;
    next = next->next;
    dec_ref_cnt(current->data);
    dec_ref_cnt(current);
  }
  dll->current_position = NULL;
  dll->begin = NULL;
  dll->end = NULL;
  dll->length = 0;
}

void UTIL_DLL_Initialize(dll_struct *dll) 
{
  dll->begin            = NULL;
  dll->current_position = NULL;
  dll->end              = NULL;
  dll->length           = 0;
}

void UTIL_DLL_Next( dll_struct *dll ) {
  if ( dll->current_position == NULL )
    return;
    dll->current_position = 
      ((dll_node_struct*)(dll->current_position))->next;
}

int32u UTIL_DLL_At_End( dll_struct *dll ) {
  if ( dll->current_position == NULL ) {
    return 1;
  }
  return 0;
}

void UTIL_DLL_Set_Begin( dll_struct *dll ) {
  dll->current_position = dll->begin;
}

void* UTIL_DLL_Get_Signed_Message( dll_struct *dll ) {
  if ( dll->current_position == NULL ) return NULL;
  return (signed_message*)dll->current_position->data;
}

int32u UTIL_DLL_Is_Empty( dll_struct *dll ) {
  if ( dll->begin == NULL ) {
    return 1;
  }
  return 0;
}

void* UTIL_DLL_Front_Message( dll_struct *dll ) {
  if ( dll->begin == NULL ) return NULL;
  return (signed_message*)(dll->begin->data);
}

void UTIL_DLL_Pop_Front( dll_struct *dll ) {
  dll_node_struct *begin;
  if  ( dll->begin != NULL ) {
    /* adjust position if necessary */
    if (dll->current_position == dll->begin) {
      dll->current_position = dll->begin->next;
    }
    if (dll->end == dll->begin ) {
      dll->end = NULL;
    }
    if ( dll->begin->data != NULL ) {
      dec_ref_cnt(dll->begin->data);
      dll->begin->data = NULL;
    }
    begin = dll->begin->next;
    dll->length--;
    dec_ref_cnt(dll->begin);
    dll->begin = begin; 
  }
}

void UTIL_DLL_Set_Last_Extra( dll_struct *dll, int32u index, int32u val ) {
  if (dll->end != NULL) {
    dll->end->extra[index] = val;
  }
}

int32u UTIL_DLL_Front_Extra( dll_struct *dll, int32u index ) {
  if ( dll->begin == NULL ) { return 0; }
  return (dll->begin->extra[index]);
}

void UTIL_DLL_Add_Data( dll_struct *dll, void *data ) {

  inc_ref_cnt( data );

  dll->length++;
    
  dll_node_struct *node;
 
  if((node = (dll_node_struct*)new_ref_cnt(DLL_NODE_OBJ))==NULL) {
    Alarm(EXIT,"UTIL_DLL_Add_Data:"
	  " Could not allocate memory for slot.\n");
  }

  if ( dll->end != NULL ) {
    dll->end->next = node;
  }
 
  if ( dll->begin == NULL ) {
    dll->begin = node;
  }
 
  node->data = data;
  node->next = NULL;
  node->extra[0] = 0;
  node->extra[1] = 0;
  UTIL_Stopwatch_Start( &(node->sw) );
  dll->end = node;

}

void UTIL_DLL_Add_Data_To_Front(dll_struct *dll, void *data) 
{
  dll_node_struct *node;

  inc_ref_cnt(data);
  dll->length++;

  if((node = (dll_node_struct *)new_ref_cnt(DLL_NODE_OBJ)) == NULL)
    Alarm(EXIT, "UTIL_DLL_Add_Data_To_Front: Could not allocate node.\n");

  node->data = data;
  node->next = dll->begin;
  dll->begin = node;
  node->extra[0] = 0;
  node->extra[1] = 0;
  
  if(dll->end == NULL)
    dll->end = node;
}

double UTIL_DLL_Elapsed_Front( dll_struct *dll ) 
{
  if ( dll->begin == NULL ) 
    return 0;
  UTIL_Stopwatch_Stop(&(dll->begin->sw));
  return UTIL_Stopwatch_Elapsed(&(dll->begin->sw));
}
