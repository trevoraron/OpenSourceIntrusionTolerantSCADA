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


/* Demo */

/*#include "prime_demo_include.h"*/

#define START_X_BOUND 400
#define START_Y_BOUND 467
#define START_SPEED 40
#define START_DIRECTION M_PI / 4
#define DIAMETER 40



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


/* Demo functions */

void init( State * );
void move( State * );
void bounce( State * );
void keepInBounds( State * );
void Init_Demo();
void Demo_Connection_Acceptor( int, int, void* );
void Receive_From_Client( int, int, void* );
void Send_Init(int);
/* ----- Demo Parameters ----- */

/* Server properties */
State               state;
unsigned int        id, sequence = 0;
uint16_t            id_bitmask = 0;
int                 ack_flag;

/* Message properties */
message_type        mess_type;
int                 mess_len, reply_len, neto_len;
char                /*mess_buf[MAX_MESS_LEN], */reply_buf[MAX_MESS_LEN];
byte                mess_buf[UPDATE_SIZE];
int                 mess_seq;
uint16_t            recv_bitmask, reply_bitmask;
Header              *hdr;
Server_Subheader    *ssub;

/* Socket vars */
struct sockaddr_in name;
int                 s;
int                 recv_s[10], temp_sock;
int                 valid[10];
fd_set              sockset;
fd_set              empty_sockset, temp_sockset;
long                on=1;
int32u              executed_updates[MAX_ACTIONS];

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
int32u executed[NUM_SERVER_SLOTS][MAX_ACTIONS];
int sd[NUM_SERVER_SLOTS];
util_stopwatch update_sw[MAX_ACTIONS];

util_stopwatch sw;
util_stopwatch latency_sw;
signed_message *pending_update;
double Latencies[NUM_SERVER_SLOTS][MAX_ACTIONS];
FILE *fp;
int32 num_of_updates = 0;

void clean_exit(int signum)
{
  Alarm(PRINT, "Received signal %d\n", signum);
  fflush(stdout);
  exit(0);
}

int main(int argc, char** argv) 
{
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
  /* Init Demo */
  Init_Demo();
  
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

  /*Run_Client();*/
  memset( executed_updates, 0, sizeof(int32u) * MAX_ACTIONS );
  memset(executed, 0, sizeof(int32u) * NUM_SERVER_SLOTS * MAX_ACTIONS);
  send_to_server = My_Server_ID;

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

    Send_Init(sd[i]);
  }
}

void Send_Init(int sock) {
  signed_message *init;
  update_message *update_specific;

  init             = UTIL_New_Signed_Message();
  init->machine_id = My_Client_ID;
  init->len        = sizeof(update_message) + UPDATE_SIZE;
  init->type       = INIT;

  update_specific = (update_message*)(init + 1);
  update_specific->server_id  = send_to_server;
  update_specific->time_stamp = 0; 
  update_specific->address    = NET.My_Address;
  update_specific->port       = NET.Client_Port;

  init->mt_num   = 1;
  init->mt_index = 1;

  TCP_Write(sock, init, sizeof(signed_update_message));

  dec_ref_cnt(init);
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

// The following code is commented out for Prime demo.
//  if(r->machine_id != My_Client_ID) {
//    Alarm(PRINT, "Received response not intended for me!\n");
//    return 0;
//  }

  /* Do not send repeat messages */
  if ( executed_updates[r->client_seq_num] != 0 ) {
    Alarm( DEBUG, "Already executed update %d\n", r->client_seq_num );
    return 0;
  }

  if(executed[r->machine_id][r->seq_num] != 0) {
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
  byte *params;
//  int k,ret;

  response_specific = (client_response_message *)(mess+1);
  params = (byte *)(response_specific +1);

  UTIL_Stopwatch_Stop(&update_sw[response_specific->seq_num]);
  time = UTIL_Stopwatch_Elapsed(&update_sw[response_specific->seq_num]);

  Alarm(PRINT, "Executed operation num. %d\n", response_specific->client_seq_num);

//  Latencies[response_specific->machine_id][response_specific->seq_num] = time;
  executed[response_specific->machine_id][response_specific->seq_num]  = 1;

  /* Mark as sent */
  executed_updates[response_specific->client_seq_num] = 1;

  switch ( response_specific->message_type ) {
            case MOVE:
                move( &state );

                /*printf( "Recieved: MOVE\n" );*/
                break;
            case BOUNDS:
                memcpy( &state.x_bounds, params, 
                        sizeof(state.x_bounds) );
                memcpy( &state.y_bounds,
                        (params + sizeof(state.x_bounds)), 
                        sizeof(state.y_bounds) );
                keepInBounds( &state );

                /*printf( "Recieved: BOUNDS\n" );*/
                break;
            case SPEED:
                memcpy( &state.speed, mess_buf, sizeof(state.speed) );

                /*printf( "Recieved: SPEED\n" );*/
                break;
            case COLOR:
                memcpy( &state.color, mess_buf, sizeof(state.color) );

                /*printf( "Recieved: COLOR\n" );*/
                break;
            case INIT: case MY_STATE: case ACK: case MAL: break;
  }

         /* Check send reply */
         /* 
          * We send a reply to the GUI client just during normal operations.
          * We avoid overwhelming the GUI client with many reply messages.  
          */
         if(response_specific->recovery == 1)
           return;
         /*if ( reply_bitmask & id_bitmask ) {*/
            hdr = (Header *) reply_buf;
            hdr->length = sizeof(Header) + sizeof(Server_Subheader);
            hdr->message_type = MY_STATE;
            ssub = (Server_Subheader *)( reply_buf + sizeof(Header) );
            ssub->seq = response_specific->client_seq_num /*sequence*/;
            ssub->state = state;

            reply_len = hdr->length;

            /*printf( "Reply length: %d\n", reply_len );*/
                            
            send( recv_s[0], reply_buf, reply_len, 0 );

        /*}*/

  

//  if(response_specific->seq_num % PRINT_INTERVAL == 0)
//    Alarm(PRINT, "%d\t%f\n", response_specific->seq_num, time);
  
  /*num_outstanding_updates--;*/
  /* Marco 5/14/2014: send a message for each emulated client */
/*  if(num_of_updates < MAX_ACTIONS)
    Send_Update(0, NULL);
  else {
    sleep(3);
    CLIENT_Cleanup();
  }
*/  /* end */

  return;
}

/*void Run_Client()
{
  memset(executed, 0, sizeof(int32u) * NUM_SERVER_SLOTS * MAX_ACTIONS);

  num_outstanding_updates = 0;

  if(My_Server_ID != 0)
    send_to_server = My_Server_ID;
  else
    send_to_server = 1;
  Send_Update(0, NULL);
}*/

void Send_Update(int dummy, void *dummyp)
{
  signed_message *update;
  update_message *update_specific;
  byte *buf;
  int ret;

  num_outstanding_updates = 0;

  /*while(num_outstanding_updates < NUM_CLIENTS_TO_EMULATE) {*/
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

    update_specific->seq_num = mess_seq;
    update_specific->message_type = mess_type;

    buf = (byte *)(update_specific + 1);
    if ( neto_len ) memcpy( buf, mess_buf, neto_len );
    
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

    /*num_outstanding_updates++;
  }*/
}

void CLIENT_Cleanup()
{
// This part of the code is commented out for Prime demo
/*
  int32u i, j;
  int32u num_executed;
  double sum;

  num_executed = 0;
  sum          = 0.0;

  fprintf(stdout, "Cleaning up...\n");
  fflush(stdout);

  for(i = 1; i <= NUM_SERVERS; i++) {
    for(j = 0; j < time_stamp; j++) {
      if(executed[i][j]) {
        sum += Latencies[i][j];
        num_executed++;
      }
    }
  }

  Alarm(PRINT, "%d: %d updates\tAverage Latency: %f\n", 
	My_Client_ID, num_executed, (sum / (double)num_executed));
  fflush(stdout);

  fprintf(fp, "%f %d\n", (sum / (double)num_executed), num_executed);
  fsync(fileno(fp));
*/
  exit(0);
}

double Compute_Average_Latency()
{
  int32u i, j;
  double sum = 0.0;

  Alarm(DEBUG, "Action count in Compute(): %d\n", time_stamp);

  for(i = 1; i <= NUM_SERVERS; i++) {
    for(j = 1; j < time_stamp; j++) {
      if(Latencies[i][j] > 0.004) {
        Alarm(DEBUG, "High latency for update %d: %f\n", i, Latencies[i][j]);
      }
      sum += Latencies[i][j];
    }
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



/************************************
 *
 *State Server
 *
 * *********************************/

void Init_Demo()
{
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s<0) {
        perror("Net_server: socket error");
        exit(1);
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
        perror("Net_server: setsockopt error \n");
        exit(1);
    }

    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(PORT);

    if ( bind( s, (struct sockaddr *)&name, sizeof(name) ) < 0 ) {
        perror("Net_server: bind error");
        exit(1);
    }
 
    if ( listen(s, 4) < 0 ) {
        perror("Net_server: listen error");
        exit(1);
    }

    E_attach_fd( s, READ_FD, Demo_Connection_Acceptor, 0, NULL, MEDIUM_PRIORITY );

}

void Demo_Connection_Acceptor( int sock, int dummy_int, void *dummy )
{
    struct sockaddr_in  from;
    socklen_t           from_size;
    int                 i;

    from_size = sizeof(from);
    for ( i = 0; i < 10; i++ ) {
        if ( recv_s[i] == 0 ) {
            recv_s[i] = accept( sock, (struct sockaddr *)&from, &from_size );
            E_attach_fd( recv_s[i], READ_FD, Receive_From_Client, 0, NULL, 
                         MEDIUM_PRIORITY );
            return;
        }
    }
}


void Receive_From_Client( int sock, int dummy_int, void *dummy )
{
//    State   temp_state;
    int     k,ret;

    /* Unwrap header */
    if( recv( sock, &mess_len, sizeof(mess_len), 0 ) > 0) {
        recv( sock, &mess_type, sizeof(mess_type), 0 );

        /* Unwrap sub-header */
        recv( sock, &mess_seq, sizeof(mess_seq), 0 );
        recv( sock, &recv_bitmask, sizeof(recv_bitmask), 0 );
        recv( sock, &reply_bitmask, sizeof(reply_bitmask), 0 );

        /* Recieve remaining content, if any */
        neto_len = mess_len - sizeof(Header) - sizeof(Client_Subheader);
        if ( neto_len > 0 ) recv( sock, mess_buf, neto_len, 0 );
        /*mess_buf[neto_len] = '\0';*/

        /*printf( "Server %d\n", id );
        printf( "Neto len: %d\n", neto_len );

        printf( "Message type is %d\n", mess_type );*/
        /*printf("len is :%d  message is : %s \n ", mess_len, mess_buf);*/

        /* Commit action */
        switch ( mess_type ) {
            case INIT:
                init( &state );
                /*memcpy( &id, mess_buf, sizeof(id) );*/
                id_bitmask = 1 << My_Client_ID;
                ack_flag = 1;

                /*perror( "Recieved: INIT\n" );*/
                /*printf( "ID: %u\n", My_Client_ID );*/
                break;
            case MOVE:
                /*move( &state );*/
                Send_Update( 0, NULL );

                /*printf( "Recieved: MOVE\n" );*/
                break;
            case MY_STATE:
                printState( state );

                /*printf( "Recieved: STATE\n" );*/
                break;
            case BOUNDS:
                /*memcpy( &state.x_bounds, mess_buf, 
                        sizeof(state.x_bounds) );
                memcpy( &state.y_bounds,
                        (mess_buf + sizeof(state.x_bounds)), 
                        sizeof(state.y_bounds) );
                keepInBounds( &state );*/
                Send_Update( 0, NULL );

                /*printf( "Recieved: BOUNDS\n" );*/
                break;
            case SPEED:
                memcpy( &state.speed, mess_buf, sizeof(state.speed) );

                /*printf( "Recieved: SPEED\n" );*/
                break;
            case COLOR:
                memcpy( &state.color, mess_buf, sizeof(state.color) );

                /*printf( "Recieved: COLOR\n" );*/
                break;
            case MAL:
                perror( "MAL recieved" );
                memcpy( &state.x_bounds, mess_buf, 
                        sizeof(state.x_bounds) );
                memcpy( &state.y_bounds,
                        (mess_buf + sizeof(state.x_bounds)), 
                        sizeof(state.y_bounds) );
                keepInBounds( &state );

                /*memcpy( &temp_state, mess_buf, sizeof(temp_state) );
                printState( temp_state );
                if ( temp_state.speed < 200 ) state.speed = temp_state.speed;
                if ( temp_state.x_bounds > 0 ) state.x_bounds = temp_state.x_bounds;
                if ( temp_state.y_bounds > 0 ) state.y_bounds = temp_state.y_bounds;
                if ( temp_state.color >= 0 ) state.color = temp_state.color;*/
                break;
            case ACK: break;
        } 

        sequence++; /* For now */

        temp_sock = sock;
        /* Check send reply */
        /*if ( reply_bitmask & id_bitmask ) {*/
            hdr = (Header *) reply_buf;
            hdr->length = sizeof(Header) + sizeof(Server_Subheader);
            hdr->message_type = ( ack_flag ) ? ACK : MY_STATE;
            ssub = (Server_Subheader *)( reply_buf + sizeof(Header) );
            ssub->seq = sequence;
            ssub->state = state;

            reply_len = hdr->length;

            /*printf( "Reply length: %d\n", reply_len );*/
                            
            if ( ack_flag ) {
                /* Send ACKs to all */
                for ( k = 0; k < 10; k++ ) {
                    if ( recv_s[k] > 0 ) {
                        ret = send( recv_s[k], reply_buf, reply_len, 0 );
                        if ( ret != reply_len ) 
                            perror( "Net_server: error in reply" );
                        else perror( "Net_server: ACK sent" );
                    }
                }
            } /*else send( sock, reply_buf, reply_len, 0 );*/

            ack_flag = 0;
            /*printf( "Sent!\n" );*/
        /*}*/

        /*printf("---------------- \n");*/
    }

}

void init( State *state )
{
    state->x_bounds = START_X_BOUND;
    state->y_bounds = START_Y_BOUND;
    state->x = state->x_bounds / 2;
    state->y = state->y_bounds / 2;
    state->direction = START_DIRECTION;
    state->speed = START_SPEED;
    state->color = BLUE;
}

/* Increments the position of the state, changing direction if needed for bounce */
void move( State *state )
{
    bounce( state );
    state->x += state->speed * cos( (double)state->direction );
    state->y += state->speed * sin( state->direction );
    keepInBounds( state );
}

void bounce( State *state )
{
    float normal;
    
    if ( state->x <= 0 ) 
        normal = 0;
    else if ( (state->x + DIAMETER) >= state->x_bounds ) 
        normal = M_PI;
    else if ( state->y <= 0 )
        normal = M_PI / 2;
    else if ( (state->y + DIAMETER) >= state->y_bounds ) 
        normal = 3 * M_PI / 2;
    else return;

    state->direction = 2 * normal - state->direction - M_PI;

    /* Normalize direction */
    while ( state->direction < 0 || state->direction >= 2 * M_PI )
        state->direction += (state->direction < 0) ? (2 * M_PI) : (-2 * M_PI);
}

/* Keeps position within the bounds of the state */
void keepInBounds( State *state )
{
    if ( state->x < 0 ) 
        state->x = 0;
    else if ( (state->x + DIAMETER) > state->x_bounds ) 
        state->x = state->x_bounds - DIAMETER;
    
    if ( state->y < 0 ) 
        state->y = 0;
    else if ( (state->y + DIAMETER) > state->y_bounds ) 
        state->y = state->y_bounds - DIAMETER;
}

