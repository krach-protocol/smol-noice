#ifndef _SN_MSG_H_
#define _SN_MSG_H_


#include <inttypes.h>
#include "sc_err.h"
typedef struct{
    uint16_t msgLen;
    uint8_t* msgBuf;
} sn_msg_t,sn_buffer_t;


//Padding
sc_err_t padBuffer(sn_buffer_t*);
sc_err_t unpadBuffer(sn_buffer_t*);


#endif