#include "queue.h"
#include "sn_msg.h"

queue_err_e messageInQueue(queue_t* queue){
    if(queue->queueIdx == queue->queueLen-1){
        return FULL;
    }else if(queue->queueIdx > 0){
        return DATA_AVAILIBLE;
    }else{
        return EMPTY;
    }

}

queue_err_e getMessageFromQueue(queue_t* queue, uint8_t* data){
    if(queue->queueIdx == 0){
        return EMPTY;
    } else {
        data = queue->data[queue->queueIdx];
        queue->queueIdx--;
        return OK;
    return 0;
    }
}
queue_err_e addToQueue(queue_t* queue, uint8_t* data){
return OK;
}


queue_t* initQueue(uint8_t queueLen){
    queue_t *queue = (queue_t*)malloc(sizeof(queue_t));
    queue->dataSize = sizeof(sn_msg_t);
    queue->queueIdx=0;
    queue->data = (uint8_t**)malloc(queueLen);
    queue->queueLen=queueLen;

    return queue;
}
