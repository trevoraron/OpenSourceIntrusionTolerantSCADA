/*
 * message_queue.h contains the definition of the methods used 
 * to manage scada messages received from the Data Acquisition Daemon.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 3/27/2015
 */

#include "scada_packets.h"

#define QUEUE_SIZE 50

typedef struct dummy_queue_node {
  scada_message *mess;
  struct dummy_queue_node *next;
} queue_node;

int Enqueue(scada_message *);
scada_message *Dequeue();
scada_message *Top();
