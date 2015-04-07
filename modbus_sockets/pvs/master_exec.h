/*
 * master_exec.h contains the definition of the 
 * methods used for the execution of the SCADA 
 * master server.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 4/02/2015
 */

typedef struct // (todo: define your data structure here)
{
  int val[32];
  int testval;
  const char *toolTip[32];
  int *toolValues;
}
DATA;

void Init_Master(DATA *);
int Read_From_DAD(int);
int Write_To_DAD(int, unsigned int, unsigned int, unsigned int, int);
