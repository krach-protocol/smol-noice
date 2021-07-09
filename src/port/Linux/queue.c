#include "../queue.h"
#include "sn_msg.h"

#include <stdio.h>

queue_err_e messageInQueue(queue_t* queue){
    queue_err_e err = EMPTY;
     if(queue->queueIdx > 0){
        printf("data in Queue availible\n");
        err =  DATA_AVAILIBLE;
    }else{
        err =  EMPTY;
    }
    return err;
}

queue_err_e getMessageFromQueue(queue_t* queue, sn_msg_t** data){
    queue_err_e err = OK;
    if(queue->queueIdx == 0){
        err = EMPTY;
    } else {
        *data = queue->data[--queue->queueIdx];
        err = OK;
    }
    return err;
}
queue_err_e addToQueue(queue_t* queue, sn_msg_t* data){
    queue_err_e err = OK;
    
    if(queue->queueIdx >= queue->queueLen){
        err = FULL; 
    }else{
        queue->data[queue->queueIdx] = data;
        queue->queueIdx++;
        printf("new Element in queue\n");
        err = OK;
    }
    return err;
}


queue_t* initQueue(uint8_t queueLen){
    queue_t *queue = (queue_t*)malloc(sizeof(queue_t));
    queue->queueIdx=0;
    queue->data = (sn_msg_t**)malloc(sizeof(sn_msg_t*)*queueLen);
    queue->queueLen=queueLen;

    return queue;
}
