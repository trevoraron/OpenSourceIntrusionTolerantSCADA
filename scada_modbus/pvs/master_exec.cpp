/*
 * master_exec.c contains the implementation of the 
 * methods used for the execution of the SCADA 
 * master server.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 4/20/2015
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "master_exec.h"

extern "C" {
  #include "../helpers/scada_packets.h"
  #include "../helpers/TCP_Wrapper.h"
}

#define MY_ID 1

void Process_Message(int, scada_message *);
DATA *d = NULL;
int seq_num = 0;

void Init_Master(DATA *dd) {
  d = dd;
}

int Read_From_DAD(int s) {
  int ret, remaining_bytes; 
  char buf[1024];
  scada_message *mess;

  ret = TCP_Read(s, buf, sizeof(scada_message));
  if(ret <= 0) {
    perror("Reading error");
    close(s);
    return ret;
  }

  mess = ((scada_message *)buf);
  remaining_bytes = (int)mess->len;
  ret = TCP_Read(s, &buf[sizeof(scada_message)], remaining_bytes);
  if(ret <= 0) {
    perror("Reading error");
    close(s);
    return ret;
  }
  Process_Message(s, (scada_message *)buf);

  return ret;
}

int Write_To_DAD(int s, unsigned int var, unsigned int slave_id, unsigned int start_add, int value) {
  int ret, nBytes;
  scada_message *mess = NULL;

  mess = PKT_Construct_Modbus_TCP_Mess(FEEDBACK, var, slave_id, start_add, value);
  mess->seq_num = ++seq_num;
  mess->sender_id = MY_ID;
  nBytes = mess->len + sizeof(scada_message);

  printf("Write to RTU: var=%d, slave_id=%d, start_add=%d, value=%d\n", var, slave_id, start_add, value);

  ret = TCP_Write(s, mess, nBytes);
  if(ret <= 0) {
    perror("Writing error");
    close(s);
  }

  free(mess);
  return ret;
}

void Process_Message(int s, scada_message *mess) {
  modbus_tcp_mess *mod;
  char *str;
  char name[100];

  mod = (modbus_tcp_mess *)(mess + 1);

  // There are two kinds of messages received from RTU
  // 1) COIL_STATUS: specifies if a switch is open/closed
  // 2) INPUT_REGISTERS: contains the voltage frequency 
  //    and its offset of two different transformer. These 
  //    values are stored in two vectors. The mod->start_add 
  //    parameter determines if the value is a frequency
  //    if the transformer is the primary 
  //    (mod->start_add = 0, primary transformer - 
  //    mod->start_add = 1, backup transformer) 
  //    or an offset (mod->start_add = 2 or mod->start_add = 3 
  //    for primary and backup respectively).
  if(d != NULL) {
    if(mod->var == COIL_STATUS) {
      d->tx_switch = mod->value;
    }
    else if(mod->var == INPUT_REGISTERS) {
      // Voltage
      if(mod->start_add == 0 || mod->start_add == 1) {
        (*d->data_lists)[mod->start_add].push_back(mod->value);
        if((*d->data_lists)[mod->start_add].size() > LEN_STORED)
          (*d->data_lists)[mod->start_add].erase((*d->data_lists)[mod->start_add].begin());
      }
      // Offset
      else {
        (*d->offsets)[mod->start_add - 2].push_back(mod->value);
        if((*d->offsets)[mod->start_add - 2].size() > LEN_STORED)
          (*d->offsets)[mod->start_add - 2].erase((*d->offsets)[mod->start_add - 2].begin());
      }
    }
  }

  str = Var_Type_To_String(mod->var);
  sprintf(name, "%s(%d,%d)", str, mod->slave_id, mod->start_add);
  free(str);
  printf("mess %d on socket %d: %s = %d\n", mess->seq_num, s, name, mod->value);
}

