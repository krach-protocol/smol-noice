#ifndef _SN_MSG_H_
#define _SN_MSG_H_

#include <inttypes.h>

typedef struct{
    uint16_t msgLen;
    uint8_t* msgBuf;
} sn_msg_t;

#endif