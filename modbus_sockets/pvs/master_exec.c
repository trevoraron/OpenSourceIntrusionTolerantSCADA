/*
 * master_exec.c contains the implementation of the 
 * methods used for the execution of the SCADA 
 * master server.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 4/03/2015
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "master_exec.h"
#include "../helpers/scada_packets.h"
#include "../helpers/TCP_Wrapper.h"

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
  int i;

  mod = (modbus_tcp_mess *)(mess + 1);
  str = Var_Type_To_String(mod->var);
  sprintf(name, "%s(%d,%d)", str, mod->slave_id, mod->start_add);
  free(str);

  if(d != NULL) {
    for(i = 1; i < 32; i++) {
      if(strcmp(d->toolTip[i], name) == 0) {
        d->toolValues[i] = mod->value;
        break;
      }
    }
  }
  printf("mess %d on socket %d: %s = %d\n", mess->seq_num, s, name, mod->value);
}

