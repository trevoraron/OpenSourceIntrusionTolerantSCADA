/*
 * master_exec.c contains the implementation of the 
 * methods used for the execution of the SCADA 
 * master server.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 4/27/2015
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

void Validate_Message(signed_message *);
void Process_SCADA_Message(signed_message *);
void Order_Message(signed_message *);

DATA *d = NULL;
unsigned int prime_seq_num = 0;
unsigned int scada_seq_num = 0;
unsigned int executed[10001];

// extern variables for socket communication
extern int dad_sock;
extern int prime_sock;
extern int My_Client_ID;
extern int My_Server_ID;
extern int Client_Port;
extern int My_Address;

void Init_Master() {
  memset(executed, 0, 10001);
  d = (DATA *)malloc(sizeof(DATA));
  memset(d, 0, sizeof(DATA));

  d->data_lists = new vector<vector<double> >(NUM_STREAMS, vector<double>());
  d->offsets = new vector<vector<double> >(NUM_STREAMS, vector<double>());
  for(int i = 0; i < LEN_STORED; i++) {
    d->overfr[i] = 61.5;
    d->underfr[i] = 58.5;
  }
  d->tx_switch = -1;

  sleep(1);
  Conn_To_Prime();
}

DATA *Get_DATA_Ptr() {
  return d;
}

int Read_Message(int s) {
  int ret, remaining_bytes; 
  char buf[1024];
  signed_message *mess;

  ret = TCP_Read(s, buf, sizeof(signed_message));
  if(ret <= 0) {
    perror("Reading error");
    close(s);
    return ret;
  }

  mess = ((signed_message *)buf);
  remaining_bytes = (int)mess->len;
  ret = TCP_Read(s, &buf[sizeof(signed_message)], remaining_bytes);
  if(ret <= 0) {
    perror("Reading error");
    close(s);
    return ret;
  }
  Validate_Message((signed_message *)buf);

  return ret;
}

int Write_Message(int s, signed_message *mess, int nBytes) {
  int ret;

  ret = TCP_Write(s, mess, nBytes);
  if(ret <= 0) {
    perror("Writing error");
    close(s);
  }

  return ret;
}

void Conn_To_Prime() {
  // This is a dummy update message that is sent 
  // to initialize the connection with a Prime server
  signed_message *mess = PKT_Construct_Signed_Message(sizeof(signed_update_message));
  mess->len = sizeof(signed_update_message);
  mess->type = DUMMY;
  mess->machine_id = My_Client_ID;

  Write_Message(prime_sock, mess, sizeof(signed_update_message));
  free(mess);
}

void Validate_Message(signed_message *mess) {
  if(mess->type == MODBUS_TCP)
    Order_Message(mess);
  else if (mess->type == CLIENT_RESPONSE)
    Process_SCADA_Message(mess);
}

void Process_SCADA_Message(signed_message *mess) {
  client_response_message *res;
  signed_message *scada_mess;
  modbus_tcp_mess *mod;
  char *str;
  char name[100];
  int nBytes;

  res = (client_response_message*)(mess + 1);
  scada_mess = (signed_message *)(res + 1);
  mod = (modbus_tcp_mess *)(scada_mess + 1);

  // Discard the message if already processed
  if(executed[mod->seq_num] != 0)
    return;
  executed[mod->seq_num] = 1;

  // If the message is a feedback, send it to the RTU
  // otherwise process it locally
  if(mod->type == FEEDBACK) {
    d->tx_switch = mod->value;
    nBytes = mess->len + sizeof(signed_message);
    if(Write_Message(dad_sock, scada_mess, nBytes) > 0)
      printf("Write to RTU: var=%d, slave_id=%d, start_add=%d, value=%d\n", mod->var, mod->slave_id, mod->start_add, mod->value);
    return;
  }

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
  printf("mess %d: %s = %d\n", res->seq_num, name, mod->value);
}

void Send_Feedback(unsigned int var, unsigned int slave_id, unsigned int start_add, int value) {
  signed_message *mess;

  mess = PKT_Construct_Modbus_TCP_Mess(FEEDBACK, ++scada_seq_num, var, slave_id, start_add, value);
  mess->machine_id = My_Client_ID;

  Order_Message(mess);
  free(mess);
}

void Order_Message(signed_message *mess) {
  signed_message *update;
  update_message *update_specific;
  unsigned char *buf;
  int nBytes;

  // Create a Prime update
  update = PKT_Construct_Signed_Message(sizeof(update_message) + UPDATE_SIZE);
  update->machine_id = My_Client_ID;
  update->len = sizeof(update_message) + UPDATE_SIZE;
  update->type = UPDATE;

  update_specific = (update_message*)(update+1);

  update_specific->server_id = My_Server_ID;
  update_specific->time_stamp = ++prime_seq_num; 
  update_specific->address = My_Address;
  update_specific->port = Client_Port;

  // copy the content of the received message in the update message
  buf = (unsigned char *)(update_specific + 1);
  memcpy(buf, mess, sizeof(signed_message) + sizeof(modbus_tcp_mess));
  nBytes = sizeof(signed_update_message);

  Write_Message(prime_sock, update, nBytes);
  free(update);
}

