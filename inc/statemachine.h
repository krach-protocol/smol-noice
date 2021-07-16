#ifndef __STATEMACHINE_H__
#define __STATEMACHINE_H__

#include "sc_err.h"
#include "smol-noice.h"
typedef enum{INIT_NETWORK,SEND_INIT,WAIT_FOR_RES,SEND_FIN,DO_TRANSPORT,ERROR} handshakeStep;

sc_err_t sc_init(smolNoice_t* smolNoice);

#endif