#ifndef _PORT_H_SC_
#define _PORT_H_SC_
#include "sn_msg.h"


void startTask(void* (void*),void*);

uint8_t openSocket(char*,uint8_t);
void sendOverNetwork(sn_msg_t*);
uint8_t messageFromNetwork(sn_msg_t*);


#endif