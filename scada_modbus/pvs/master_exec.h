/*
 * master_exec.h contains the definition of the 
 * methods used for the execution of the SCADA 
 * master server.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 4/17/2015
 */

#include <vector>
#include <cmath>
#include <cstdlib>
#include <iostream>
#define NUM_STREAMS 2
#define LEN_STORED 100
using namespace std;

typedef struct // (todo: define your data structure here)
{
  int tx_A_status;
  int tx_B_status;
  double overfr[LEN_STORED];
  double underfr[LEN_STORED];
  vector<vector<double> > * data_lists;
}
DATA;

void Init_Master(DATA *);
int Read_From_DAD(int);
int Write_To_DAD(int, unsigned int, unsigned int, unsigned int, int);
