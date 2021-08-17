#ifndef _LINUX_QUEUE_H_
#define _LINUX_QUEUE_H_

#include <inttypes.h>
#include <stdlib.h>
#include "sn_msg.h"

/*
typedef struct{
    uint8_t queueLen;
    uint8_t readIdx;
    uint8_t writeIdx;
    uint8_t elementsInQueue;
    sn_msg_t** data;
    char* queueName;
} queue_t;
*/

typedef struct {
    size_t head;
    size_t tail;
    size_t size;
    sn_buffer_t** data;
    char* queueName;
} queue_t;


typedef enum{EMPTY,DATA_AVAILIBLE,FULL, QUEUE_OK,NO_MEM} queue_err_e;

queue_t* initQueue(uint8_t);

/*
queue_err_e messageInQueue(queue_t*);
queue_err_e getMessageFromQueue(queue_t*,sn_msg_t**);
queue_err_e addToQueue(queue_t*,uint8_t*,uint8_t);
*/
queue_err_e queue_read(queue_t *,sn_buffer_t**);
queue_err_e queue_write(queue_t *, sn_buffer_t*);
queue_err_e queue_peek(queue_t* queue);
#endif