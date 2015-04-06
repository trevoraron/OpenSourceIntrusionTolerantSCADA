/***************************************************************************
 *   client for Modbus with pvbrowser                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "rlmodbus.h"
#include "rlthread.h"
#include "rlinifile.h"
#include "rlspreadsheet.h"
#include "rlsocket.h"
#include "rlserial.h"

#include <sys/socket.h>
#include <sys/time.h>

extern "C" {
  #include "../helpers/scada_packets.h"
  #include "../helpers/TCP_Wrapper.h"
}

// global values
static char               var[80]                  = "";
static int                debug                    = 1;    // 0 or 1
static int                cycletime                = 1000; // milliseconds
static int                use_socket               = 1;
static char               buf[1024];
static int                poll_slave_counter[256];
static int                n_poll_slave             = 1;    // poll always

// values for RTU socket
static char               ip[80]                   = "192.168.1.115";
static int                port                     = 0;

// values for tty/
static char               devicename[1024]         = "/dev/ttyS0";
static int                baudrate                 = B9600;
static int                rtscts                   = 1;
static int                stopbits                 = 1;
static int                parity                   = 0;
static int                protocol                 = rlModbus::MODBUS_RTU;

// values from rllib...
rlSpreadsheetRow          *namelist                 = NULL;    
int                       *namelist_count, *namelist_slave, *namelist_function, *namelist_start_adr, *namelist_datasize;
int                        num_cycles               = 0;
int                        max_name_length          = 31;
rlThread                  *thread                   = NULL;
rlModbus                  *modbus                   = NULL;
rlSocket                  *mysocket                 = NULL;
rlSerial                  *tty                      = NULL;

// values for pvs sockets
#define PORT 5555
#define PVS_ADDRESS "127.0.0.1"
#define MY_ID 1
int sock;
int seq_num = 0;

// values for synchronizing reads 
// and writes from/to shared variables
pthread_mutex_t rtu_v_mutex;

struct rtu_sample {
  unsigned int var;
  unsigned int slave_id;
  unsigned int start_add;
  int val;
};

struct rtu_status {
  struct timeval ts;
  struct rtu_sample *sample_list;  
};

struct rtu_status *rtu_s;

static int modbus_idletime = (4*1000)/96;

static int Write_To_PVS(unsigned int var, unsigned int s_id, unsigned int add, int v) {
  int ret, nBytes;
  scada_message *mess;

  mess = PKT_Construct_Modbus_TCP_Mess(READ_DATA, var, s_id, add, v);
  mess->seq_num = ++seq_num;
  mess->sender_id = MY_ID;
  nBytes = mess->len + sizeof(scada_message);

  ret = TCP_Write(sock, mess, nBytes);
  if(ret <= 0) {
    perror("Writing error");
    close(sock);
  }

  free(mess);
  return ret;
}

static void *socketWriteThread(void *arg) {
  int i;
  struct timeval last_ts;

  if(arg != NULL)
    return NULL;

  last_ts.tv_sec = 0;
  last_ts.tv_usec = 0;

  while(1) {
    // enter critical section
    pthread_mutex_lock(&rtu_v_mutex);
    // send a message to the pvs only if there's something new in the rtu_struct
    if((last_ts.tv_sec > rtu_s->ts.tv_sec) || (last_ts.tv_sec == rtu_s->ts.tv_sec && last_ts.tv_usec >= rtu_s->ts.tv_usec))
      goto skip;
    for(i = 0; i < num_cycles; i++) {
      if(Write_To_PVS(rtu_s->sample_list[i].var, rtu_s->sample_list[i].slave_id, rtu_s->sample_list[i].start_add, rtu_s->sample_list[i].val) < 0)
        perror("Impossible to write data to the PVS");
    }
    skip:
    pthread_mutex_unlock(&rtu_v_mutex);
    // critical section ends here
    sleep(1);
  }

  pthread_exit(NULL);
}

static void *socketReadThread(void *arg) {
  if(arg != NULL)
    return NULL;

  char buf[1024], data[4], temp[1024];
  int ret, val, slave, function, adr, buflen, doit, remaining_bytes;
  fd_set active_fd_set;
  scada_message *mess;
  modbus_tcp_mess *mod;

  FD_ZERO(&active_fd_set);
  FD_SET(sock, &active_fd_set);

  while(1) {
    if(select(FD_SETSIZE, &active_fd_set, NULL, NULL, NULL) > 0) {
      if(FD_ISSET(sock, &active_fd_set)) {
        ret = TCP_Read(sock, temp, sizeof(scada_message));
        if(ret < 0) {
          perror("Reading error");
          close(sock);
          break;
        }

        mess = ((scada_message *)temp);
        remaining_bytes = (int)mess->len;
        ret = TCP_Read(sock, &temp[sizeof(scada_message)], remaining_bytes);
        if(ret < 0) {
          perror("Reading error");
          close(sock);
          break;
        }

        mess = ((scada_message *)temp);
        mod = (modbus_tcp_mess *)(mess + 1);
        slave = (int)mod->slave_id;
        adr = (int)mod->start_add;
        val = mod->value;
        doit = 0;

        if(mod->var == COIL_STATUS) {
          function     = rlModbus::ForceSingleCoil;
          data[0] = adr/256; data[1] = adr & 0x0ff;
          data[2] = 0; data[3] = 0;
          if(val != 0) data[2] = 0x0ff;
          buflen = 4;
          doit = 1;
        }  
        else if(mod->var == HOLDING_REGISTERS) {
          function     = rlModbus::PresetSingleRegister;
          data[0] = adr/256; data[1] = adr & 0x0ff;
          data[2] = val/256; data[3] = val & 0x0ff;
          buflen = 4;
          doit = 1;
        }
        else {
        printf("USER_ERROR: unknown %s entered\n", buf);
        printf("Possible values:\n");
        printf("coil(slave,adr)\n");
        printf("register(slave,adr)\n");
        }

        if(doit) {
          thread->lock();
          if(use_socket != 1) rlsleep(modbus_idletime); // on tty we have to sleep
          if(debug) printf("modbus_write: slave=%d function=%d data[0]=%d\n", slave, function, data[0]);
          ret = modbus->write( slave, function, (const unsigned char *) data, buflen);
          ret = modbus->response( &slave, &function, (unsigned char *) buf);
          if(use_socket != 1) rlsleep(modbus_idletime); // on tty we have to sleep
          thread->unlock();
          if(ret < 0) perror("Write to RTU: error");
          rlsleep(10); // sleep in order that reading can work in parallel even if we are sending a lot of data
        }  
      }
    }
  }
  pthread_exit(NULL);  
}

static int init(int ac, char **av)
{
  int i;
  const char *text, *cptr;
  char *cptr2;
  if(ac != 2)
  {
    printf("usage: %s inifile\n", av[0]);
    return -1;
  }

  for(i=0; i<256; i++) poll_slave_counter[i] = 0;

  rlIniFile ini;
  if(ini.read(av[1]) != 0)
  {
    printf("could not open %s\n", av[1]);
    return -1;
  }

  // init global variables
  use_socket  = atoi(ini.text("GLOBAL","USE_SOCKET"));
  debug       = atoi(ini.text("GLOBAL","DEBUG"));
  cycletime   = atoi(ini.text("GLOBAL","CYCLETIME"));
  cptr = ini.text("GLOBAL","N_POLL_SLAVE");
  if(isdigit(*cptr))
  {
    n_poll_slave = atoi(cptr);
  }

  // init socket variables
  strcpy(ip,         ini.text("SOCKET","IP"));
  port        = atoi(ini.text("SOCKET","PORT"));

  // init tty variables
  strcpy(devicename, ini.text("TTY","DEVICENAME"));
  text        =      ini.text("TTY","BAUDRATE");
  baudrate    = B9600; modbus_idletime = (4*1000)/96;
  if(strcmp(text,"300" )   == 0) { baudrate = B300;    modbus_idletime = (4*1000)/3;    }    
  if(strcmp(text,"600" )   == 0) { baudrate = B600;    modbus_idletime = (4*1000)/6;    }
  if(strcmp(text,"1200")   == 0) { baudrate = B1200;   modbus_idletime = (4*1000)/12;   }
  if(strcmp(text,"1800")   == 0) { baudrate = B1800;   modbus_idletime = (4*1000)/18;   }
  if(strcmp(text,"2400")   == 0) { baudrate = B2400;   modbus_idletime = (4*1000)/24;   }
  if(strcmp(text,"4800")   == 0) { baudrate = B4800;   modbus_idletime = (4*1000)/48;   }
  if(strcmp(text,"9600")   == 0) { baudrate = B9600;   modbus_idletime = (4*1000)/96;   }
  if(strcmp(text,"19200")  == 0) { baudrate = B19200;  modbus_idletime = (4*1000)/192;  }
  if(strcmp(text,"38400")  == 0) { baudrate = B38400;  modbus_idletime = (4*1000)/384;  }
  if(strcmp(text,"57600")  == 0) { baudrate = B57600;  modbus_idletime = (4*1000)/576;  }
  if(strcmp(text,"115200") == 0) { baudrate = B115200; modbus_idletime = (4*1000)/1152; }
  rtscts      = atoi(ini.text("TTY","RTSCTS"));
  text        =      ini.text("TTY","PARITY");
  if     (strcmp(text,"EVEN") == 0)  parity = rlSerial::EVEN;
  else if(strcmp(text,"ODD")  == 0)  parity = rlSerial::ODD;
  else                               parity = rlSerial::NONE;
  text        =  ini.text("TTY","STOPBITS");
  if(*text == '1') stopbits = 1;
  if(*text == '2') stopbits = 2;
  text        =      ini.text("TTY","PROTOCOL");
  if     (strcmp(text,"ASCII") == 0) protocol = rlModbus::MODBUS_ASCII;
  else                               protocol = rlModbus::MODBUS_RTU;

  printf("%s starting with debug=%d cycletime=%d use_socket=%d n_poll_slave=%d\n",
         av[0],            debug,   cycletime,   use_socket, n_poll_slave);

  // init values for rllib...
  num_cycles = atoi(ini.text("CYCLES","NUM_CYCLES"));
  if(num_cycles <= 0)
  {
    printf("num_cycles=%d <= 0\n", num_cycles);
    return -1;
  }
  if(debug) printf("num_cycles=%d\n", num_cycles);
  namelist = new rlSpreadsheetRow();

  namelist_count         = new int[num_cycles];
  namelist_slave         = new int[num_cycles];
  namelist_function      = new int[num_cycles];
  namelist_start_adr     = new int[num_cycles];
  namelist_datasize      = new int[num_cycles];

  for(i=0; i<num_cycles; i++)
  {
    sprintf(buf,"CYCLE%d",i+1);
    text = ini.text("CYCLES",buf);
    cptr = strchr(text,',');
    if(cptr == NULL)
    {
      printf("no , given on CYCLE %s\n", text);
      return -1;
    }
    cptr++;
    sscanf(text,"%d", &namelist_count[i]);
    if(debug) printf("CYCLE%d=%s count=%d name=%s\n", i+1, text, namelist_count[i], cptr);
    if(strlen(cptr) >= sizeof(var)-1)
    {
      printf("%s too long. exit\n", cptr);
      return -1;
    }
    strcpy(var,cptr);
    cptr2 = strchr(var,'(');
    if(cptr2 == NULL)
    {
      printf("no ( given on CYCLE %s\n", text);
      return -1;
    }
    *cptr2 = '\0';
    cptr2++;
    sscanf(cptr2,"%d,%d", &namelist_slave[i], &namelist_start_adr[i]);
    if     (strcmp(var,"coilStatus"       ) == 0)
    {
      namelist_function[i] = rlModbus::ReadCoilStatus;
      namelist_datasize[i] = 1;  // bit
    }
    else if(strcmp(var,"inputStatus"      ) == 0)
    {
      namelist_function[i] = rlModbus::ReadInputStatus;
      namelist_datasize[i] = 1;  // bit
    }
    else if(strcmp(var,"holdingRegisters" ) == 0)
    {
      namelist_function[i] = rlModbus::ReadHoldingRegisters;
      namelist_datasize[i] = 16; // bit 
    }
    else if(strcmp(var,"inputRegisters"   ) == 0)
    {
      namelist_function[i] = rlModbus::ReadInputRegisters;
      namelist_datasize[i] = 16; // bit 
    }
    else
    {
      printf("%s(slave,start_adr) not implemented !\n", var);
      printf("Possible names:\n");
      printf("coilStatus(slave,start_adr)\n");
      printf("inputStatus(slave,start_adr)\n");
      printf("holdingRegisters(slave,start_adr)\n");
      printf("inputRegisters(slave,start_adr)\n");
      return -1;
    }
    namelist->printf(i+1,"%s",var);
  } 

  max_name_length = atoi(ini.text("RLLIB","MAX_NAME_LENGTH"));
  if(max_name_length < 4)
  {
    printf("max_name_length=%d < 4\n", max_name_length);
    return -1;
  }
  if(debug) printf("max_name_length=%d\n", max_name_length);

  thread = new rlThread();
  modbus = new rlModbus(1024,protocol);
  if(use_socket)
  {
    mysocket = new rlSocket(ip,port,1);
    modbus->registerSocket(mysocket);
    mysocket->connect();
    if(mysocket->isConnected()) printf("success connecting to %s:%d\n", ip, port);
    else                        printf("WARNING: could not connect to %s:%d\n", ip, port);
  }
  else
  {
    tty = new rlSerial();
    if(tty->openDevice(devicename,baudrate,1,rtscts,8,stopbits,parity) < 0)
    {
      printf("ERROR: could not open device=%s\n", devicename);
      printf("check if you have the necessary rights to open %s\n", devicename);
      return -1;
    }
    modbus->registerSerial(tty);
  }

  return 0;
}

static int modbusCycle(int slave, int function, int start_adr, int num_register, unsigned char *data)
{
  int ret;

  if(slave < 0 || slave >= 256) return -1;
  if(poll_slave_counter[slave] > 0)
  {
    if(debug) printf("modbusCycle not polling slave%d: poll_slave_counter[%d]=%d\n", slave, slave, poll_slave_counter[slave]);
    poll_slave_counter[slave] -= 1;
    if(poll_slave_counter[slave] != 0) 
      return -1;
  }

  if(debug) printf("modbusRequest: var=%s : slave=%d function=%d start_adr=%d num_register=%d\n", 
                                   var,     slave,   function,   start_adr,   num_register);
  if(use_socket != 1) rlsleep(modbus_idletime); // on tty we have to sleep
  thread->lock();
  ret = modbus->request(slave, function, start_adr, num_register);
  if(ret >= 0) ret = modbus->response( &slave, &function, data);
  thread->unlock();
  if(ret < 0)
    poll_slave_counter[slave] = n_poll_slave;
  if(debug) printf("modbusResponse: ret=%d slave=%d function=%d data=%02x %02x %02x %02x\n",
                                    ret,   slave,   function,   data[0], data[1], data[2], data[3]);
  return ret;
}

static int readModbus(int i)
{
  unsigned char data[512]; 
  int           i1, ind, ret;
  unsigned int  val = 0, start_add = 0;

  ret = modbusCycle(namelist_slave[i], namelist_function[i], namelist_start_adr[i], namelist_count[i], data);

  if(ret < 0)
  {
    if(debug) printf("modbusCycle returned error\n");
    return ret;
  }
  ind = 0;
  for(i1=0; i1<namelist_count[i]; )
  {
    start_add = namelist_start_adr[i] + i1;
    if     (namelist_datasize[i] == 1)  // bit
    {
      val = data[ind];
      ind += 1;
      i1  += 8;
    }
    else if(namelist_datasize[i] == 16) // bit
    {
      val = data[ind]*256 + data[ind+1];
      ind += 2;
      i1  += 1;
    }
    else
    {
      printf("ERROR: unknown datasize\n");
      return -1;
    }
    // write the RTU status on the shared struct
    rtu_s->sample_list[i].var = Var_Type_To_Int(var);
    rtu_s->sample_list[i].slave_id = (unsigned int)namelist_slave[i];
    rtu_s->sample_list[i].start_add = (unsigned int)start_add;
    rtu_s->sample_list[i].val = (int)val;
    // update ts
    gettimeofday(&rtu_s->ts, NULL);
  }
  return 0;
}

int main(int argc,char *argv[])
{
  rlSpreadsheetCell *cell;
  int i;

  if(init(argc, argv) != 0)
  {
    return -1;
  }

  // connect to the pvs
  struct sockaddr_in pvs;
  pthread_t tid[2];

  if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Socket error");
    exit(EXIT_FAILURE);
  }

  bzero(&pvs, sizeof(pvs));
  pvs.sin_family = AF_INET;
  pvs.sin_port = htons(PORT);
  pvs.sin_addr.s_addr = inet_addr(PVS_ADDRESS);

  if(connect(sock, (struct sockaddr *)&pvs, sizeof(pvs)) < 0) {
    perror("Connection error");
    exit(EXIT_FAILURE);
  }

  pthread_mutex_init(&rtu_v_mutex, NULL);
  rtu_s = (rtu_status *)malloc(sizeof(rtu_status));
  rtu_s->ts.tv_sec = 0;
  rtu_s->ts.tv_usec = 0;
  rtu_s->sample_list = (rtu_sample *)malloc(num_cycles * sizeof(rtu_sample));
  memset(rtu_s->sample_list, 0, num_cycles * sizeof(rtu_sample));
  pthread_create(&tid[0], NULL, &socketWriteThread, NULL);
  pthread_create(&tid[1], NULL, &socketReadThread, NULL);

  // forever run the daemon
  while(1)
  {
    cell = namelist->getFirstCell();

    // enter the critical section to read 
    // from RTU and store the RTU status
    pthread_mutex_lock(&rtu_v_mutex);
    for(i=0; i<num_cycles; i++)
    {
      if(cell == NULL) break;
      strcpy(var,cell->text());
      readModbus(i);
      cell = cell->getNextCell();
    }
    pthread_mutex_unlock(&rtu_v_mutex);
    // critical section ends here

    rlsleep(cycletime);
  }

  free(rtu_s->sample_list);
  pthread_mutex_destroy(&rtu_v_mutex);
  pthread_exit(NULL);
  return 0;
}

