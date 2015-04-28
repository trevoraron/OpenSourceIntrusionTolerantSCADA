//###############################################################
//# mask1_slots.h for ProcessViewServer created: Thu Apr 16 16:40:20 2015
//# please fill out these slots
//# here you find all possible events
//# Yours: Lehrig Software Engineering
//###############################################################

#include "master_exec.h"

extern "C" {
  #include "../helpers/scada_packets.h"
}

DATA *data;

static int slotInit(PARAM *p, DATA *d)
{
  if(p == NULL || d == NULL) return -1;
  memset(d, 0, sizeof(DATA)); // makes the compiler happy!

  // This overrides the empty DATA d provided by mask1.cpp
  data = Get_DATA_Ptr();

  qpwInsertCurve(p, tx_A, 0, "Transformer A");
  qpwSetCurvePen(p, tx_A, 0, GREEN, 4);
  qpwInsertCurve(p, tx_B, 1, "Transformer B");
  qpwSetCurvePen(p, tx_B, 1, GREEN, 4);
  // Overfrequency/underfrequency curves
  qpwInsertCurve(p, tx_A, 2, "Underfrequency Tran A");
  qpwSetCurvePen(p, tx_A, 2, RED, 4);
  qpwInsertCurve(p, tx_A, 3, "Overfrequency Tran A");
  qpwSetCurvePen(p, tx_A, 3, RED, 4);
  qpwInsertCurve(p, tx_B, 4, "Underfrequency Tran B");
  qpwSetCurvePen(p, tx_B, 4, RED, 4);
  qpwInsertCurve(p, tx_B, 5, "Overfrequency Tran B");
  qpwSetCurvePen(p, tx_B, 5, RED, 4);

  return 0;
}

static int slotNullEvent(PARAM *p, DATA *d)
{
  if(p == NULL || d == NULL) return -1;

  if(data->tx_switch == 0) {
    pvPrintf(p,tx_A_but,"Disabled");
    pvPrintf(p,tx_B_but,"Enabled");
  }
  else if(data->tx_switch == 1) {  
    pvPrintf(p,tx_A_but,"Enabled");
    pvPrintf(p,tx_B_but,"Disabled");
  }
  else {
    pvPrintf(p,tx_A_but,"Unknown");
    pvPrintf(p,tx_B_but,"Unknown");
  }

  // Graph diagram
  int i; 
  unsigned int z;
  double x_vals[LEN_STORED];
  double y_vals[LEN_STORED];
  double last[LEN_STORED];
  for(i = 0; i < NUM_STREAMS; i++) {
    for(z = 0; z < (*data->data_lists)[i].size(); z++) {
      x_vals[z] = z;
      y_vals[z] = (*data->data_lists)[i][z] + 0.01 * (*data->offsets)[i][z];
      last[i] = y_vals[z];
    }
    if(i == 0) {
     // Compare the last value to thresholds and display an alarm if necessary
      if(last[i] > 0 && (last[i] < 58.5 || last[i] > 61.5)) {
        pvSetBackgroundColor(p, tx_A_lab, 255, 0, 0);
        qpwSetCurvePen(p, tx_A, 0, BLUE, 4);
      }
      else {
        pvSetBackgroundColor(p, tx_A_lab, 0, 255, 0);
        qpwSetCurvePen(p, tx_A, 0, GREEN, 4);
      }
      qpwSetCurveData(p, tx_A, 2, (*data->data_lists)[i].size(), x_vals, data->underfr);
      qpwSetCurveData(p, tx_A, 3, (*data->data_lists)[i].size(), x_vals, data->overfr);
      qpwSetCurveData(p, tx_A, i, (*data->data_lists)[i].size(), x_vals, y_vals);
    }
    else {
      // Compare the last value to thresholds and display an alarm if necessary
      if(last[i] > 0 && (last[i] < 58.5 || last[i] > 61.5)) {
        pvSetBackgroundColor(p, tx_B_lab, 255, 0, 0);
        qpwSetCurvePen(p, tx_B, 0, BLUE, 4);
      }
      else {
        pvSetBackgroundColor(p, tx_B_lab, 0, 255, 0);
        qpwSetCurvePen(p, tx_B, 0, GREEN, 4);
      }
      qpwSetCurveData(p, tx_B, 4, (*data->data_lists)[i].size(), x_vals, data->underfr);
      qpwSetCurveData(p, tx_B, 5, (*data->data_lists)[i].size(), x_vals, data->overfr);
      qpwSetCurveData(p, tx_B, i, (*data->data_lists)[i].size(), x_vals, y_vals);
    }
  }
  qpwReplot(p, tx_A);
  qpwReplot(p, tx_B);

  return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;

  int sw;
  if(id == tx_A_but || id == tx_B_but) {
    if(data->tx_switch == 0)
      sw = 1;
    else
      sw = 0;
    Send_Feedback(COIL_STATUS, 1, 0, sw);
  }

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
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
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
