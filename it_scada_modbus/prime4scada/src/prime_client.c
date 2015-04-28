
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
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *
 * Copyright (c) 2008 - 2014
 * The Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Prime research was provided by the Defense Advanced
 * Research Projects Agency (DARPA) and The National Security Agency (NSA).
 * Prime is not necessarily endorsed by DARPA or the NSA.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <signal.h>
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "net_types.h"
#include "objects.h"
#include "network.h"
#include "packets.h"
#include "data_structs.h"
#include "utility.h"
#include "tcp_wrapper.h"
#include "merkle.h"

/* The behavior of the client can be controlled with parameters that follow */

/* A single client process can be made to act like several clients by
 * having multiple requests outstanding at one time.  After sending
 * the specified number of requests, the client does not send a new
 * one until it receives a response to one of the previous ones. */
#define NUM_CLIENTS_TO_EMULATE 1

/* Adjust this to configure how often a client prints. */
#define PRINT_INTERVAL NUM_CLIENTS_TO_EMULATE

/* This sets the maximum number of updates a client can submit */
#define MAX_ACTIONS BENCHMARK_END_RUN

/* Local Functions */
int Prime_Client(int argc, char **argv);
void Usage(int argc, char **argv);
void Print_Usage (void);
void Init_Memory_Objects(void);
void Init_Network(void); 
void Net_Cli_Recv(channel sk, int dummy, void *dummy_p); 
void Process_Message( signed_message *mess, int32u num_bytes );
void Run_Client(void);
void Send_Update(int dummy, void *dummyp);
void CLIENT_Cleanup(void);
int max_rcv_buff(int sk);
int max_snd_buff(int sk);
int32u Validate_Message( signed_message *mess, int32u num_bytes ); 
double Compute_Average_Latency(void);
void clean_exit(int signum);

/* Client Variables */
extern network_variables NET;

int32u My_Client_ID;
int32u My_Server_ID;

int32u update_count;
double total_time;
int32u time_stamp;

/* Local buffers for receiving the packet */
static sys_scatter srv_recv_scat;
static sys_scatter ses_recv_scat;

int32u num_outstanding_updates;
int32u send_to_server;
int32u last_executed = 0;
int32u executed[MAX_ACTIONS];
int sd[NUM_SERVER_SLOTS];
util_stopwatch update_sw[MAX_ACTIONS];

util_stopwatch sw;
util_stopwatch latency_sw;
signed_message *pending_update;
double Latencies[MAX_ACTIONS];
FILE *fp;
int32 num_of_updates = 0;

void clean_exit(int signum)
{
  Alarm(PRINT, "Received signal %d\n", signum);
  fflush(stdout);
  exit(0);
}

int Prime_Client(int argc, char** argv) 
{

  Alarm(PRINT, "\n");
  Alarm(PRINT, "/===========================================================================\\\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| Prime.                                                                    |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| The contents of this file are subject to the Prime Open-Source            |\n");
  Alarm(PRINT, "| License, Version 1.0 (the ''License''); you may not use                   |\n");
  Alarm(PRINT, "| this file except in compliance with the License.  You may obtain a        |\n");
  Alarm(PRINT, "| copy of the License at:                                                   |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| http://www.dsn.jhu.edu/byzrep/prime/LICENSE.txt                           |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| Software distributed under the License is distributed on an AS IS basis,  |\n");
  Alarm(PRINT, "| WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License  |\n");
  Alarm(PRINT, "| for the specific language governing rights and limitations under the      |\n");
  Alarm(PRINT, "| License.                                                                  |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| Creators:                                                                 |\n");
  Alarm(PRINT, "|  Yair Amir            yairamir@cs.jhu.edu                                 |\n");
  Alarm(PRINT, "|  Jonathan Kirsch      jak@cs.jhu.edu                                      |\n");
  Alarm(PRINT, "|  John Lane            johnlane@cs.jhu.edu                                 |\n");
  Alarm(PRINT, "|  Marco Platania       platania@cs.jhu.edu                                 |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| Major Contributors:                                                       |\n");
  Alarm(PRINT, "|  Brian Coan           Design of the Prime algorithm                       |\n");
  Alarm(PRINT, "|  Jeff Seibert         View Change protocol                                |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| Copyright (c) 2008 - 2014                                                 |\n");
  Alarm(PRINT, "| The Johns Hopkins University.                                             |\n");
  Alarm(PRINT, "| All rights reserved.                                                      |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "| Partial funding for Prime research was provided by the Defense Advanced   |\n");
  Alarm(PRINT, "| Research Projects Agency (DARPA) and The National Security Agency (NSA).  |\n");
  Alarm(PRINT, "| Prime is not necessarily endorsed by DARPA or the NSA.                    |\n");
  Alarm(PRINT, "|                                                                           |\n");
  Alarm(PRINT, "\\===========================================================================/\n\n");

  char buf[128];

  Usage(argc, argv);
  Alarm_set_types(PRINT);

  NET.program_type = NET_CLIENT_PROGRAM_TYPE;
  update_count     = 0;
  time_stamp       = 0;
  total_time       = 0;

  UTIL_Load_Addresses(); 

  E_init(); 
  Init_Memory_Objects();
  Init_Network();
  
  OPENSSL_RSA_Init();
  OPENSSL_RSA_Read_Keys( My_Client_ID, RSA_CLIENT ); 
  
  sprintf(buf, "latencies/client_%d.lat", My_Client_ID);
  fp = fopen(buf, "w");
    
  signal(SIGINT,  clean_exit);
  signal(SIGTERM, clean_exit);
  signal(SIGKILL, clean_exit);
  signal(SIGQUIT, clean_exit);
  signal(SIGHUP,  clean_exit);
  signal(SIGTSTP, clean_exit);
  signal(SIGTTOU, clean_exit);
  signal(SIGTTIN, clean_exit);

  Run_Client();

  Alarm(PRINT, "%d entering event system.\n", My_Client_ID);
  fflush(stdout);
  E_handle_events();

  Alarm(PRINT, "%d finishing!!!\n", My_Client_ID);
  fflush(stdout);

  return 0;
}

void Init_Memory_Objects(void)
{
  /* Initialize memory object types  */
  Mem_init_object_abort(PACK_BODY_OBJ, "packet",      sizeof(packet),      100, 1);
  Mem_init_object_abort(SYS_SCATTER,   "sys_scatter", sizeof(sys_scatter), 100, 1);
}

void Usage(int argc, char **argv)
{
  char ip_str[16];
  int i1, i2, i3, i4;
  int tmp;

  NET.My_Address = -1;
  My_Client_ID   =  0;
  My_Server_ID   =  0;

  while(--argc > 0) {
    argv++;
    
    /* [-l A.B.C.D] */
    if((argc > 1) && (!strncmp(*argv, "-l", 2))) {
      sscanf(argv[1], "%s", ip_str);
      sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      NET.My_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
      argc--; argv++;
    }
    /* [-i client_id] */
    else if((argc > 1)&&(!strncmp(*argv, "-i", 2))) {
      sscanf(argv[1], "%d", &tmp);
      My_Client_ID = tmp;
      if(My_Client_ID > NUM_CLIENTS || My_Client_ID <= 0) {
	Alarm(PRINT, "Client ID must be between 1 and %d\n", NUM_CLIENTS);
	exit(0);
      }
      argc--; argv++;
    }
    /* [-s server_id] */
    else if((argc > 1)&&(!strncmp(*argv, "-s", 2))) {
      sscanf(argv[1], "%d", &tmp);
      My_Server_ID = tmp;
      if(My_Server_ID > NUM_SERVERS || My_Server_ID <= 0) {
	Alarm(PRINT, "Server ID must be between 1 and %d\n", NUM_SERVERS);
	exit(0);
      }
      argc--; argv++;
    }
    else {
      Print_Usage();
    }
  }

  /* Both -l and -i arguments are mandatory */
  if(My_Client_ID == 0 || NET.My_Address == -1)
    Print_Usage();

  /* Port is computed as a function of the client id */
  NET.Client_Port = PRIME_CLIENT_BASE_PORT + My_Client_ID;

  Alarm(PRINT, "Client %d, IP = "IPF", Port = %d\n", 
	My_Client_ID, IP(NET.My_Address), NET.Client_Port);
  if(My_Server_ID == 0)
    Alarm(PRINT, "Rotating updates across all servers.\n");
  else
    Alarm(PRINT, "Sending updates to server %d only.\n", My_Server_ID);

  /* Seed the random number generator */
  srand(My_Client_ID);
}

void Print_Usage()
{
  Alarm(PRINT, "Usage: ./client\n"
	"\t -l IP (A.B.C.D) \n"
        "\t -i client_id, indexed base 1\n"
	"\t[-s server_id, indexed base 1]\n");

  exit(0);
}


/***********************************************************/
/* void Init_Network(void)                                 */
/*                                                         */
/* First thing that gets called. Initializes the network   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Init_Network(void) 
{
  struct sockaddr_in server_addr;
  int32u i;
  
  /* Initialize the receiving scatters */
  srv_recv_scat.num_elements    = 1;
  srv_recv_scat.elements[0].len = sizeof(packet);
  srv_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(srv_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
  
  ses_recv_scat.num_elements    = 1;
  ses_recv_scat.elements[0].len = sizeof(packet);
  ses_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(ses_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
  
  /* Initialize the sockets, one per server in my site */
  
  for(i = 1; i <= NUM_SERVERS; i++) {

    /* If we're sending to a particular server, set up a connection
     * with that server only. */
    if(My_Server_ID != 0 && i != My_Server_ID)
      continue;

    if((sd[i] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      fflush(stdout);
      exit(0);
    }

    assert(sd[i] != fileno(stderr));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(PRIME_TCP_BASE_PORT + i);
    server_addr.sin_addr.s_addr = htonl(UTIL_Get_Server_Address(i));
    
    if((connect(sd[i], (struct sockaddr *)&server_addr, 
		sizeof(server_addr))) < 0) {
      perror("connect");
      Alarm(PRINT, "Client %d could not connect to server server %d\n", 
	    My_Client_ID, i);
      fflush(stdout);
      exit(0);
    }
    Alarm(PRINT, "Client %d connected to server %d\n", My_Client_ID, i);

    /* Register the socket descriptor with the event system */
    E_attach_fd(sd[i], READ_FD, Net_Cli_Recv, 0, NULL, MEDIUM_PRIORITY);

    /* Maximize the size of the socket buffers */
    max_rcv_buff(sd[i]);
    max_snd_buff(sd[i]);
  }
}

/***********************************************************/
/* void Net_Cli_Recv(channel sk, int dummy, void *dummy_p) */
/*                                                         */
/* Called by the event system to receive data from socket  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket                                         */
/* dummy:   not used                                       */
/* dummy_p: not used                                       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Net_Cli_Recv(channel sk, int dummy, void *dummy_p) 
{
  int32  received_bytes;
  int32u expected_total_size, remaining_bytes;
  int    ret;

  /* First read the signed message part (header), which can be used
   * to determine the length of the rest of the message. */
  ret = TCP_Read(sk, srv_recv_scat.elements[0].buf, 
		 sizeof(signed_message));
  if(ret <= 0) {
    Alarm(DEBUG, "%d read returned %d\n", My_Client_ID, ret);
    close(sk);
    E_detach_fd(sk, READ_FD);
    CLIENT_Cleanup();
  }

  expected_total_size = 
    UTIL_Message_Size((signed_message *)srv_recv_scat.elements[0].buf);

  remaining_bytes = expected_total_size - sizeof(signed_message);

  Alarm(DEBUG, "Read %d bytes so far, expecting total size of %d\n",
	ret, expected_total_size);

  ret = TCP_Read(sk, &srv_recv_scat.elements[0].buf[sizeof(signed_message)], 
		 remaining_bytes);
  if(ret <= 0) {
    Alarm(PRINT, "%d read returned %d\n", My_Client_ID, ret);
    fflush(stdout);
    close(sk);
    E_detach_fd(sk, READ_FD);
    CLIENT_Cleanup();
  }

  received_bytes = expected_total_size;
  Alarm(DEBUG, "Received %d TCP bytes!\n", received_bytes);
  
  /* Validate the client response */
  if(!Validate_Message((signed_message*)srv_recv_scat.elements[0].buf, 
		       received_bytes)) {
    Alarm(DEBUG,"CLIENT VALIDATION FAILURE\n");
    return;
  }

  /* Now process the message */
  Process_Message( (signed_message*)(srv_recv_scat.elements[0].buf),  
		   received_bytes);
  
  if(get_ref_cnt(srv_recv_scat.elements[0].buf) > 1) {
    dec_ref_cnt(srv_recv_scat.elements[0].buf);
    if((srv_recv_scat.elements[0].buf = 
	(char *) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
      Alarm(EXIT, "Net_Srv_Recv: Could not allocate packet body obj\n");
    }
  }
}

int32u Validate_Message( signed_message *mess, int32u num_bytes ) 
{
  client_response_message *r;
  int ret;
  
  if(mess->type != CLIENT_RESPONSE) {
    Alarm(PRINT, "Invalid response type: %d\n", mess->type);
    return 0;
  }

  /* Size should be at least signed update message */
  if(num_bytes < (sizeof(signed_message) + sizeof(client_response_message))) {
    Alarm(PRINT, "Response too small: only %d bytes\n", num_bytes);
    return 0;
  }

  r = (client_response_message *)(mess+1);

  if(r->machine_id != My_Client_ID) {
    Alarm(PRINT, "Received response not intended for me!\n");
    return 0;
  }

  if(executed[r->seq_num] != 0) {
    Alarm(PRINT, "Already processed response for seq %d\n", r->seq_num);
    return 0;
  }

  /* Check the signature */
  ret = MT_Verify(mess);

  if(ret == 0) {
    Alarm(PRINT, "Signature on client response message did not verify!\n");
    return 0;
  }

  return 1;  
}

void Process_Message( signed_message *mess, int32u num_bytes ) 
{
  client_response_message *response_specific;
  double time;

  response_specific = (client_response_message *)(mess+1);

  UTIL_Stopwatch_Stop(&update_sw[response_specific->seq_num]);
  time = UTIL_Stopwatch_Elapsed(&update_sw[response_specific->seq_num]);

  Latencies[response_specific->seq_num] = time;
  executed[response_specific->seq_num]  = 1;

  if(response_specific->seq_num % PRINT_INTERVAL == 0)
    Alarm(PRINT, "%d\t%f\n", response_specific->seq_num, time);
  
  num_outstanding_updates--;
  /* Marco 5/14/2014: send a message for each emulated client */
  if(num_of_updates < MAX_ACTIONS)
    Send_Update(0, NULL);
  else {
    sleep(3);
    CLIENT_Cleanup();
  }
  /* end */

  return;
}

void Run_Client()
{
  memset(executed, 0, sizeof(int32u) * MAX_ACTIONS);

  num_outstanding_updates = 0;

  if(My_Server_ID != 0)
    send_to_server = My_Server_ID;
  else
    send_to_server = 1;
  Send_Update(0, NULL);
}

void Send_Update(int dummy, void *dummyp)
{
  signed_message *update;
  update_message *update_specific;
  int ret;

  while(num_outstanding_updates < NUM_CLIENTS_TO_EMULATE) {
    num_of_updates++;

    /* Build a new update */
    update             = UTIL_New_Signed_Message();
    update->machine_id = My_Client_ID;
    update->len        = sizeof(update_message) + UPDATE_SIZE;
    update->type       = UPDATE;

    update_specific = (update_message*)(update+1);

    time_stamp++; 
    update_specific->server_id  = send_to_server;
    update_specific->time_stamp = time_stamp; 
    update_specific->address    = NET.My_Address;
    update_specific->port       = NET.Client_Port;

    /* Start the clock on this update */
    UTIL_Stopwatch_Start(&update_sw[time_stamp]);

    /* Sign the message */
    update->mt_num   = 1;
    update->mt_index = 1;

    if(CLIENTS_SIGN_UPDATES)
      UTIL_RSA_Sign_Message(update);

    Alarm(PRINT, "%d Sent %d to server %d\n", 
	  My_Client_ID, time_stamp, send_to_server);

    /* Send the update to a local server in your local site */
    ret = TCP_Write(sd[send_to_server], update, sizeof(signed_update_message));
    if(ret <= 0) {
      perror("write");
      fflush(stdout);
      close(sd[send_to_server]);
      E_detach_fd(sd[send_to_server], READ_FD);
      CLIENT_Cleanup();
    }
    
    dec_ref_cnt(update);

    /* If we're rotating across all servers, send the next one to the 
     * next server modulo the total number of servers. */
    if(My_Server_ID == 0) {

#if 0
      send_to_server++;
      send_to_server = send_to_server % (NUM_SERVERS);
#endif
      send_to_server = rand() % NUM_SERVERS;
      if(send_to_server == 0)
	send_to_server = NUM_SERVERS;
    }

    num_outstanding_updates++;
  }
}

void CLIENT_Cleanup()
{
  int32u i;
  int32u num_executed;
  double sum;

  num_executed = 0;
  sum          = 0.0;

  fprintf(stdout, "Cleaning up...\n");
  fflush(stdout);

  for(i = 0; i < time_stamp; i++) {
    if(executed[i]) {
      sum += Latencies[i];
      num_executed++;
    }
  }

  Alarm(PRINT, "%d: %d updates\tAverage Latency: %f\n", 
	My_Client_ID, num_executed, (sum / (double)num_executed));
  fflush(stdout);

  fprintf(fp, "%f %d\n", (sum / (double)num_executed), num_executed);
  fsync(fileno(fp));

  exit(0);
}

double Compute_Average_Latency()
{
  int32u i;
  double sum = 0.0;

  Alarm(DEBUG, "Action count in Compute(): %d\n", time_stamp);

  for(i = 1; i < time_stamp; i++) {
    if(Latencies[i] > 0.004) {
      Alarm(DEBUG, "High latency for update %d: %f\n", i, Latencies[i]);
    }

    sum += Latencies[i];
  }

  return (sum / (double)(time_stamp-1));
}

int max_rcv_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 3000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret= getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
    if(val < i*1024 )
      break;
  }
  return(1024*(i-5));
}

int max_snd_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 3000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
    if(val < i*1024)
      break;
  }
  return(1024*(i-5));
}
