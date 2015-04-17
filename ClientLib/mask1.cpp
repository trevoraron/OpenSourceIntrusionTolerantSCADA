////////////////////////////////////////////////////////////////////////////
//
// show_mask1 for ProcessViewServer created: Sat Apr 11 21:36:43 2015
//
////////////////////////////////////////////////////////////////////////////
#include "pvapp.h"

// _begin_of_generated_area_ (do not edit -> use ui2pvc) -------------------

// our mask contains the following objects
enum {
  ID_MAIN_WIDGET = 0,
  ID_END_OF_WIDGETS
};

static const char *toolTip[] = {
  ""
};

static const char *whatsThis[] = {
  ""
};

static int generated_defineMask(PARAM *p)
{
  int w,h,depth;

  if(p == NULL) return 1;
  w = h = depth = strcmp(toolTip[0],whatsThis[0]);
  if(w==h) depth=0; // fool the compiler
  pvStartDefinition(p,ID_END_OF_WIDGETS);
  pvEndDefinition(p);
  return 0;
}

// _end_of_generated_area_ (do not edit -> use ui2pvc) ---------------------

#include "mask1_slots.h"

static int defineMask(PARAM *p)
{
  if(p == NULL) return 1;
  generated_defineMask(p);
  // (todo: add your code here)
  return 0;
}


static int showData(PARAM *p, DATA *d)
{
  if(p == NULL) return 1;
  if(d == NULL) return 1;
  return 0;
}

static int readData(DATA *d) // from shared memory, database or something else
{
  if(d == NULL) return 1;
  // (todo: add your code here)
  return 0;
}


int show_mask1(PARAM *p, int s_id)
{
  int sock_id = s_id;
  DATA d;
  char event[MAX_EVENT_LENGTH];
  char text[MAX_EVENT_LENGTH];
  char str1[MAX_EVENT_LENGTH];
  int  i,w,h,val,x,y,button,ret;
  float xval, yval;
  int alive;
  char buf[100];

  //defineMask(p);
  //rlSetDebugPrintf(1);
  //if((ret=slotInit(p,&d)) != 0) return ret;
  //readData(&d); // from shared memory, database or something else
  //showData(p,&d);
  pvClearMessageQueue(p);
  while(1)
  {
    //Poll event, send to server
    pvPollEvent(p,event);
    tcp_send(sock_id, event, strlen(event));

    //get data from server, send to browser
    tcp_rec(sock_id, buf, sizeof(buf) - 1);
    
  }
}
