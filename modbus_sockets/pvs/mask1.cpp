////////////////////////////////////////////////////////////////////////////
//
// show_mask1 for ProcessViewServer created: Do Jan 17 17:06:13 2008
//
////////////////////////////////////////////////////////////////////////////
#include "pvapp.h"

// _begin_of_generated_area_ (do not edit -> use ui2pvc) -------------------

// our mask contains the following objects
enum {
  ID_MAIN_WIDGET = 0,
  obj1,
  obj2,
  obj3,
  obj4,
  obj5,
  obj6,
  obj7,
  buttonIncrement0,
  buttonList,
  buttonIncrement1,
  buttonIncrement2,
  buttonIncrement3,
  buttonRegister,
  ID_END_OF_WIDGETS
};

// our mask contains the following widget names
  static const char *widgetName[] = {
  "ID_MAIN_WIDGET",
  "obj1",
  "obj2",
  "obj3",
  "obj4",
  "obj5",
  "obj6",
  "obj7",
  "buttonIncrement0",
  "buttonList",
  "buttonIncrement1",
  "buttonIncrement2",
  "buttonIncrement3",
  "buttonRegister",
  "ID_END_OF_WIDGETS",
  ""};

  static const char *toolTip[] = {
  "",
  "inputStatus(1,0)",
  "inputStatus(1,8)",
  "coilStatus(1,0)",
  "holdingRegisters(1,0)",
  "holdingRegisters(1,1)",
  "inputRegisters(1,0)",
  "inputRegisters(1,10)",
  "",
  "",
  "",
  "",
  "",
  "",
  ""};

  static const char *whatsThis[] = {
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  ""};

  static const int widgetType[ID_END_OF_WIDGETS+1] = {
  0,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  -1 };

static int generated_defineMask(PARAM *p)
{
  int w,h,depth;

  if(p == NULL) return 1;
  if(widgetName[0] == NULL) return 1; // suppress unused warning
  w = h = depth = strcmp(toolTip[0],whatsThis[0]);
  if(widgetType[0] == -1) return 1;
  if(w==h) depth=0; // fool the compiler
  pvStartDefinition(p,ID_END_OF_WIDGETS);

  pvQLabel(p,obj1,0);
  pvSetGeometry(p,obj1,10,10,345,30);
  pvSetText(p,obj1,pvtr("Label"));
  pvSetFont(p,obj1,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj1,pvtr("inputStatus(1,0)"));

  pvQLabel(p,obj2,0);
  pvSetGeometry(p,obj2,10,40,345,30);
  pvSetText(p,obj2,pvtr("Label"));
  pvSetFont(p,obj2,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj2,pvtr("inputStatus(1,8)"));

  pvQLabel(p,obj3,0);
  pvSetGeometry(p,obj3,10,65,345,30);
  pvSetText(p,obj3,pvtr("Label"));
  pvSetFont(p,obj3,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj3,pvtr("coilStatus(1,0)"));

  pvQLabel(p,obj4,0);
  pvSetGeometry(p,obj4,10,90,345,30);
  pvSetText(p,obj4,pvtr("Label"));
  pvSetFont(p,obj4,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj4,pvtr("holdingRegisters(1,0)"));

  pvQLabel(p,obj5,0);
  pvSetGeometry(p,obj5,10,115,345,30);
  pvSetText(p,obj5,pvtr("Label"));
  pvSetFont(p,obj5,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj5,pvtr("holdingRegisters(1,1)"));

  pvQLabel(p,obj6,0);
  pvSetGeometry(p,obj6,10,140,345,30);
  pvSetText(p,obj6,pvtr("Label"));
  pvSetFont(p,obj6,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj6,pvtr("inputRegisters(1,0)"));

  pvQLabel(p,obj7,0);
  pvSetGeometry(p,obj7,10,165,345,30);
  pvSetText(p,obj7,pvtr("Label"));
  pvSetFont(p,obj7,"Ubuntu",11,0,0,0,0);
  pvToolTip(p,obj7,pvtr("inputRegisters(1,10)"));

  pvQPushButton(p,buttonIncrement0,0);
  pvSetGeometry(p,buttonIncrement0,490,10,100,30);
  pvSetText(p,buttonIncrement0,pvtr("Increment0"));
  pvSetFont(p,buttonIncrement0,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,buttonList,0);
  pvSetGeometry(p,buttonList,355,10,130,30);
  pvSetText(p,buttonList,pvtr("List"));
  pvSetFont(p,buttonList,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,buttonIncrement1,0);
  pvSetGeometry(p,buttonIncrement1,490,50,100,30);
  pvSetText(p,buttonIncrement1,pvtr("Increment1"));
  pvSetFont(p,buttonIncrement1,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,buttonIncrement2,0);
  pvSetGeometry(p,buttonIncrement2,490,90,100,30);
  pvSetText(p,buttonIncrement2,pvtr("Increment2"));
  pvSetFont(p,buttonIncrement2,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,buttonIncrement3,0);
  pvSetGeometry(p,buttonIncrement3,490,130,100,30);
  pvSetText(p,buttonIncrement3,pvtr("Increment3"));
  pvSetFont(p,buttonIncrement3,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,buttonRegister,0);
  pvSetGeometry(p,buttonRegister,355,130,130,30);
  pvSetText(p,buttonRegister,pvtr("Register++"));
  pvSetFont(p,buttonRegister,"Ubuntu",11,0,0,0,0);


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


int show_mask1(PARAM *p)
{
  DATA d;
  char event[MAX_EVENT_LENGTH];
  char text[MAX_EVENT_LENGTH];
  char str1[MAX_EVENT_LENGTH];
  int  i,w,h,val,x,y,button,ret;
  float xval, yval;

  defineMask(p);
  //rlSetDebugPrintf(1);
  if((ret=slotInit(p,&d)) != 0) return ret;
  readData(&d); // from shared memory, database or something else
  showData(p,&d);
  while(1)
  {
    pvPollEvent(p,event);
    switch(pvParseEvent(event, &i, text))
    {
      case NULL_EVENT:
        readData(&d); // from shared memory, database or something else
        showData(p,&d);
        if((ret=slotNullEvent(p,&d)) != 0) return ret;
        break;
      case BUTTON_EVENT:
        if((ret=slotButtonEvent(p,i,&d)) != 0) return ret;
        break;
      case BUTTON_PRESSED_EVENT:
        if((ret=slotButtonPressedEvent(p,i,&d)) != 0) return ret;
        break;
      case BUTTON_RELEASED_EVENT:
        if((ret=slotButtonReleasedEvent(p,i,&d)) != 0) return ret;
        break;
      case TEXT_EVENT:
        if((ret=slotTextEvent(p,i,&d,text)) != 0) return ret;
        break;
      case SLIDER_EVENT:
        sscanf(text,"(%d)",&val);
        if((ret=slotSliderEvent(p,i,&d,val)) != 0) return ret;
        break;
      case CHECKBOX_EVENT:
        if((ret=slotCheckboxEvent(p,i,&d,text)) != 0) return ret;
        break;
      case RADIOBUTTON_EVENT:
        if((ret=slotRadioButtonEvent(p,i,&d,text)) != 0) return ret;
        break;
      case GL_INITIALIZE_EVENT:
        if((ret=slotGlInitializeEvent(p,i,&d)) != 0) return ret;
        break;
      case GL_PAINT_EVENT:
        if((ret=slotGlPaintEvent(p,i,&d)) != 0) return ret;
        break;
      case GL_RESIZE_EVENT:
        sscanf(text,"(%d,%d)",&w,&h);
        if((ret=slotGlResizeEvent(p,i,&d,w,h)) != 0) return ret;
        break;
      case GL_IDLE_EVENT:
        if((ret=slotGlIdleEvent(p,i,&d)) != 0) return ret;
        break;
      case TAB_EVENT:
        sscanf(text,"(%d)",&val);
        if((ret=slotTabEvent(p,i,&d,val)) != 0) return ret;
        break;
      case TABLE_TEXT_EVENT:
        sscanf(text,"(%d,%d,",&x,&y);
        pvGetText(text,str1);
        if((ret=slotTableTextEvent(p,i,&d,x,y,str1)) != 0) return ret;
        break;
      case TABLE_CLICKED_EVENT:
        sscanf(text,"(%d,%d,%d)",&x,&y,&button);
        if((ret=slotTableClickedEvent(p,i,&d,x,y,button)) != 0) return ret;
        break;
      case SELECTION_EVENT:
        sscanf(text,"(%d,",&val);
        pvGetText(text,str1);
        if((ret=slotSelectionEvent(p,i,&d,val,str1)) != 0) return ret;
        break;
      case CLIPBOARD_EVENT:
        sscanf(text,"(%d",&val);
        if((ret=slotClipboardEvent(p,i,&d,val)) != 0) return ret;
        break;
      case RIGHT_MOUSE_EVENT:
        if((ret=slotRightMouseEvent(p,i,&d,text)) != 0) return ret;
        break;
      case KEYBOARD_EVENT:
        sscanf(text,"(%d",&val);
        if((ret=slotKeyboardEvent(p,i,&d,val,i)) != 0) return ret;
        break;
      case PLOT_MOUSE_MOVED_EVENT:
        sscanf(text,"(%f,%f)",&xval,&yval);
        if((ret=slotMouseMovedEvent(p,i,&d,xval,yval)) != 0) return ret;
        break;
      case PLOT_MOUSE_PRESSED_EVENT:
        sscanf(text,"(%f,%f)",&xval,&yval);
        if((ret=slotMousePressedEvent(p,i,&d,xval,yval)) != 0) return ret;
        break;
      case PLOT_MOUSE_RELEASED_EVENT:
        sscanf(text,"(%f,%f)",&xval,&yval);
        if((ret=slotMouseReleasedEvent(p,i,&d,xval,yval)) != 0) return ret;
        break;
      case MOUSE_OVER_EVENT:
        sscanf(text,"%d",&val);
        if((ret=slotMouseOverEvent(p,i,&d,val)) != 0) return ret;
        break;
      case USER_EVENT:
        if((ret=slotUserEvent(p,i,&d,text)) != 0) return ret;
        break;
      default:
        printf("UNKNOWN_EVENT id=%d %s\n",i,text);
        break;
    }
  }
}
