#ifndef _PORT_H_SC_
#define _PORT_H_SC_
#include "sn_buffer.h"
#include "smol-noice.h"


void printHex(uint8_t*,uint8_t);

void startTask(void* (void*),void*);

uint8_t openSocket(smolNoice_t*);
void sendOverNetwork(smolNoice_t* ,sn_msg_t*);
uint8_t messageFromNetwork(smolNoice_t* ,sn_msg_t*);
void sleep_ms(uint16_t);


#endif