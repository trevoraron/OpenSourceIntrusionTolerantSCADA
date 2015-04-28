/*
 * scada_packets.c contains the implementation of the methods
 * used to build the messages exchanged by Process View Server, 
 * Data Acquisition Daemon, and Prime replicas through sockets.
 *
 * Creator: Marco
 * Created: 3/18/2015
 * Last modified: 4/27/2015
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scada_packets.h"

signed_message *PKT_Construct_Signed_Message(int size) {
  signed_message *mess;
  
  mess = (signed_message *)malloc(sizeof(signed_message) + size);
  memset(mess, 0, sizeof(signed_message) + size);

  mess->mt_num   = 0;
  mess->mt_index = 0; 
  mess->site_id  = 0;

  return mess;
}

signed_message *PKT_Construct_Modbus_TCP_Mess(unsigned int flag, unsigned int sn, unsigned int v, unsigned int s_id, unsigned int add, int d) {

  signed_message *mess = NULL;
  modbus_tcp_mess *modbus_mess = NULL;

  mess = PKT_Construct_Signed_Message(sizeof(modbus_tcp_mess));
  modbus_mess = (modbus_tcp_mess *)(mess + 1);

  mess->len = sizeof(modbus_tcp_mess);
  mess->type = MODBUS_TCP;

  modbus_mess->seq_num = sn;
  modbus_mess->type = flag;
  modbus_mess->var = v;
  modbus_mess->slave_id = s_id;
  modbus_mess->start_add = add;
  modbus_mess->value = d;

  return mess;
}

int Var_Type_To_Int(char var[]) {
  if(strcmp(var, "inputRegisters") == 0) return INPUT_REGISTERS;
  else if(strcmp(var, "holdingRegisters") == 0) return HOLDING_REGISTERS;
  else if(strcmp(var, "inputStatus") == 0) return INPUT_STATUS;
  else if(strcmp(var, "coilStatus") == 0) return COIL_STATUS;
  else return -1;
}

char* Var_Type_To_String(int var) {
  char *str = (char *)malloc(30 * sizeof(char));

  switch(var) {
    case 0:
      sprintf(str, "inputRegisters");
      break;
    case 1:
      sprintf(str, "holdingRegisters");
      break;
    case 2:
      sprintf(str, "inputStatus");
      break;
    case 3:
      sprintf(str, "coilStatus");
      break;
    default:
      break;
  }

  return str;
}



