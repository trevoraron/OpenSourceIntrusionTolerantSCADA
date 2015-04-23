#ifndef PROACTIVE_RECOVERY_H
#define PROACTIVE_RECOVERY_H

void RECOVERY_Initialize_Data_Structure(void);
void RECOVERY_Initialize_Catch_Up_Struct(void);
void RECOVERY_Catch_Up_Periodically(int, void *);
void RECOVERY_Dispatcher(signed_message *);
#endif
