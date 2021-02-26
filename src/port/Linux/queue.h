#ifndef _LINUX_QUEUE_H_
#define _LINUX_QUEUE_H_

#include <inttypes.h>
#include <stdlib.h>

typedef struct{
    uint8_t queueLen;
    uint8_t queueIdx;
    uint8_t mutex;
    size_t dataSize;
    uint8_t** data;
} queue_t;

typedef enum{EMPTY,DATA_AVAILIBLE,FULL, OK} queue_err_e;

queue_t* initQueue(uint8_t);

queue_err_e messageInQueue(queue_t*);
queue_err_e getMessageFromQueue(queue_t*,uint8_t*);
queue_err_e addToQueue(queue_t*,uint8_t*);
#endif