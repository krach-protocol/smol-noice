#ifndef _LINUX_QUEUE_H_
#define _LINUX_QUEUE_H_

#include <inttypes.h>
#include <stdlib.h>

#define QUEUE_LEN 10

typedef struct{
    uint8_t queueLen;
    uint8_t queueIdx;
    uint8_t mutex;
    size_t dataSize;
    void* data[QUEUE_LEN];
} queue_t;

typedef enum{EMPTY,DATA_AVAILIBLE,FULL, OK} queue_err_e;

queue_err_e messageInQueue(queue_t*);
queue_err_e getMessageFromQueue(queue_t*,void*);
queue_err_e addToQueue(queue_t*,void*);
#endif