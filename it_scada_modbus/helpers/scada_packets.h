/*
 * scada_packets.h contains the definition of data strucures and 
 * methods used to build the messages exchanged by Process View Server, 
 * Data Acquisition Daemon, and Prime replicas through sockets.
 *
 * Creator: Marco
 * Created: 3/18/2015
 * Last modified: 4/27/2015
 */

/* Definitions for compatibility with Prime */
#define DUMMY 0
#define UPDATE 9
#define CLIENT_RESPONSE 10
#define UPDATE_SIZE 200
#define SIGNATURE_SIZE 128

/*
 * Message types:
 *   DUMMY_MESS = dummy
 *   READ_DATA = message sent from a Data Acquisition Daemon to the Process View Server
 *   FEEDBACK = message sent from the Process View Server to the Data Acquisition Daemon
 */
enum message_types {DUMMY_MESS, READ_DATA, FEEDBACK};

/*
 * Protocols used in pvbrowser:
 *   DUMMY_PROT = dummy
 *   DNP3 is currently not implemented
 */
enum protocol_types {DUMMY_PROT, MODBUS_TCP, MODBUS_SERIAL, SIEMENS_TCP, SIEMENS_PPI,
		     ETHERNET_IP, EIBNET_KNX, OPC_XML_DA, PROFIBUS, CAN, DNP3};

/*
 * Type of variables used in Modbus TCP:
 *   INPUT_REGISTERS = 16-bit word, read-only
 *   HOLDING_REGISTERS = 16-bit word, read-write
 *   INPUT_STATUS = 1 bit, read-only
 *   COIL_STATUS = 1 bit, read-write
 */
enum modbus_var_types {INPUT_REGISTERS, HOLDING_REGISTERS, INPUT_STATUS, COIL_STATUS};

/* signed_message is a header for SCADA and Prime messages */
typedef struct dummy_signed_message {
  unsigned char sig[SIGNATURE_SIZE];
  unsigned short mt_num;
  unsigned short mt_index;

  unsigned int site_id;
  unsigned int machine_id; 
  
  unsigned int len;        /* length of the content */
  unsigned int type;       /* type of the message */
 
  /* Content of message follows */
} signed_message;

/* Update content. Note that an update message has almost the same
 * structure as a signed message. It has an additional content
 * structure that contains the time stamp. Therefore, an update
 * message is actually a signed_message with content of update_content
 * and the actual update data */
typedef struct dummy_update_message {
  unsigned int server_id;
  int  address;
  short  port;
  unsigned int time_stamp;
  /* the update content follows */
} update_message;

typedef struct dummy_signed_update_message {
  signed_message header;
  update_message update;
  unsigned char update_contents[UPDATE_SIZE];
} signed_update_message;

typedef struct dummy_client_response_message {
  unsigned int machine_id;
  unsigned int seq_num;
} client_response_message;

/* Modbus TCP message */
typedef struct dummy_modbus_tcp_mess {
  unsigned int seq_num;       // sequence number
  unsigned int type;          // type of message
  unsigned int var;           // type of variable
  unsigned int slave_id;      // RTU id
  unsigned int start_add;     // starting RTU register address
  int value;                  // value read from RTU
} modbus_tcp_mess;

signed_message *PKT_Construct_Signed_Message(int);
signed_message *PKT_Construct_Modbus_TCP_Mess(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, int);
int Var_Type_To_Int(char[]);
char* Var_Type_To_String(int);

