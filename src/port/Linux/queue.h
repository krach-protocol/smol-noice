#ifndef _LINUX_QUEUE_H_
#define _LINUX_QUEUE_H_

#include <inttypes.h>
#include <stdlib.h>
#include "sn_msg.h"

typedef struct{
    uint8_t queueLen;
    uint8_t queueIdx;
    uint8_t mutex;
    sn_msg_t** data;
} queue_t;

typedef enum{EMPTY,DATA_AVAILIBLE,FULL, OK} queue_err_e;

queue_t* initQueue(uint8_t);

queue_err_e messageInQueue(queue_t*);
queue_err_e getMessageFromQueue(queue_t*,sn_msg_t**);
queue_err_e addToQueue(queue_t*,sn_msg_t*);
#endif