//###############################################################
//# mask1_slots.h for ProcessViewServer created: Sun Mar 22 23:52:04 2015
//# please fill out these slots
//# here you find all possible events
//# Yours: Lehrig Software Engineering
//###############################################################

// todo: uncomment me if you want to use this data aquisiton
// also uncomment this classes in main.cpp and pvapp.h
// also remember to uncomment rllib in the project file
//extern rlModbusClient     modbus;
//extern rlSiemensTCPClient siemensTCP;
//extern rlPPIClient        ppi;

#include <vector>
#include <cmath>
#include <cstdlib>
#include <iostream>
#define NUM_STREAMS 6
#define LEN_STORED 100
using namespace std;
//These are the modbus messages
static const char *mbus_mess[] = {
  "inputStatus(1,0)",
  "inputStatus(1,8)",
  "coilStatus(1,0)",
  "holdingRegisters(1,0)",
  "holdingRegisters(1,1)",
  "inputRegisters(1,0)",
  "inputRegisters(1,10)",
};
extern rlDataAcquisition *acqui;

typedef struct // (todo: define your data structure here)
{
  vector<vector<double> > * data_lists;
  int amp;
}
DATA;


static int slotInit(PARAM *p, DATA *d)
{

  cout << "SLOT INIT \n";
  if(p == NULL || d == NULL) return -1;
  d->amp = 1;
  d->data_lists = new vector<vector<double> >(NUM_STREAMS, vector<double>());

  //Graph stuff
  cout<< "SETTING UP GRAPHS \n";
  //Outline
  qpwEnableOutline(p, Plot, 1);
  qpwSetOutlinePen(p, Plot, GREEN);

  //legend
  qpwSetAutoLegend(p, Plot, 1);
  qpwEnableLegend(p, Plot, 1);
  qpwSetLegendPos(p, Plot, 1);
  qpwSetLegendFrameStyle(p, Plot, Box|Sunken);

  //axes
  qpwSetAxisTitle(p, Plot, xBottom, "Last 100 seconds");
  qpwSetAxisTitle(p, Plot, yLeft, "Value");
 
  //Curves
  cout<< "SETTING UP CURVES \n";
  for(int i =0; i < NUM_STREAMS; i++) {
    qpwInsertCurve(p, Plot, i, mbus_mess[i]);
    //Maybe change, I was just winging the numbers, no idea how this will look
    qpwSetCurvePen(p, Plot, i, 25*i, 100, 30 * i, 4);
    qpwSetCurveYAxis(p, Plot, i, yLeft);
  }


  return 0;
}

static int slotNullEvent(PARAM *p, DATA *d)
{
  cout << "SLOT NULL EVENT \n";
  if(p == NULL || d == NULL) return -1;
  //Will get an update from each new data stream
  cout << "GETTING MODBUS DATA \n";
  for(int i = 0; i < NUM_STREAMS; i++){
    (* d->data_lists)[i].push_back(acqui->intValue(mbus_mess[i]));
    if((* d->data_lists)[i].size() > LEN_STORED) {
      (* d->data_lists)[i].erase((*d->data_lists)[i].begin());
    }
  }

  //Graph Stuff
  double x_vals[LEN_STORED];
  double y_vals[LEN_STORED];
  cout << "GETTING GRAPH VALUES \n";
  for(int i =0; i < NUM_STREAMS; i++) {
    for(int z = 0; z < (*d->data_lists)[i].size(); z++) {
      x_vals[z] = z;
      y_vals[z] = (* d->data_lists)[i][z];
    }
    qpwSetCurveData(p, Plot, i, (*d->data_lists)[i].size(), x_vals, y_vals);
  }
  cout << "REPLOT \n";
  qpwReplot(p, Plot);
  cout << "AMP " << d->amp << " \n";
  return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotButtonPressedEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotButtonReleasedEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}


static int slotTextEvent(PARAM *p, int id, DATA *d, const char *text)
{
  cout << "SLOT_TEXT_EVEN \n";
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  try {
    d->amp = atoi(text);
  }
  catch (int e) {
    cout << "String Parsing exception \n";
  }
  acqui->writeIntValue("register(1,0)", d->amp);
  return 0;
}

static int slotSliderEvent(PARAM *p, int id, DATA *d, int val)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000) return -1;
  return 0;
}

static int slotCheckboxEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}

static int slotRadioButtonEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}

static int slotGlInitializeEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotGlPaintEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotGlResizeEvent(PARAM *p, int id, DATA *d, int width, int height)
{
  if(p == NULL || id == 0 || d == NULL || width < 0 || height < 0) return -1;
  return 0;
}

static int slotGlIdleEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotTabEvent(PARAM *p, int id, DATA *d, int val)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000) return -1;
  return 0;
}

static int slotTableTextEvent(PARAM *p, int id, DATA *d, int x, int y, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000 || text == NULL) return -1;
  return 0;
}

static int slotTableClickedEvent(PARAM *p, int id, DATA *d, int x, int y, int button)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000 || button < 0) return -1;
  return 0;
}

static int slotSelectionEvent(PARAM *p, int id, DATA *d, int val, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000 || text == NULL) return -1;
  return 0;
}

static int slotClipboardEvent(PARAM *p, int id, DATA *d, int val)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000) return -1;
  return 0;
}

static int slotRightMouseEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  //pvPopupMenu(p,-1,"Menu1,Menu2,,Menu3");
  return 0;
}

static int slotKeyboardEvent(PARAM *p, int id, DATA *d, int val, int modifier)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000 || modifier < -1000) return -1;
  return 0;
}

static int slotMouseMovedEvent(PARAM *p, int id, DATA *d, float x, float y)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000) return -1;
  return 0;
}

static int slotMousePressedEvent(PARAM *p, int id, DATA *d, float x, float y)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000) return -1;
  return 0;
}

static int slotMouseReleasedEvent(PARAM *p, int id, DATA *d, float x, float y)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000) return -1;
  return 0;
}

static int slotMouseOverEvent(PARAM *p, int id, DATA *d, int enter)
{
  if(p == NULL || id == 0 || d == NULL || enter < -1000) return -1;
  return 0;
}

static int slotUserEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}
