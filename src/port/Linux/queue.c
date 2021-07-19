#include "../queue.h"
#include "sn_msg.h"

#include <stdio.h>
#include <string.h>

queue_err_e messageInQueue(queue_t* queue){
    queue_err_e err = EMPTY;
     if(queue->queueIdx > 0){
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
queue_err_e addToQueue(queue_t* queue,uint8_t* data, uint8_t dataLen){
    queue_err_e err = OK;
    sn_buffer_t* dataPaket = (sn_buffer_t*)calloc(1,sizeof(sn_buffer_t));
    dataPaket->msgLen = dataLen;
    dataPaket->msgBuf = (uint8_t*)calloc(1,dataPaket->msgLen);
    memcpy(dataPaket->msgBuf,data,dataPaket->msgLen);
    if(queue->queueIdx >= queue->queueLen){
        err = FULL; 
    }else{
        queue->data[queue->queueIdx] = dataPaket;
        queue->queueIdx++;
        err = OK;
    }
    return err;
}


queue_t* initQueue(uint8_t queueLen){
    queue_t *queue = (queue_t*)calloc(1,sizeof(queue_t));
    queue->queueIdx=0;
    queue->data = (sn_msg_t**)calloc(queueLen,sizeof(sn_msg_t*));
    queue->queueLen=queueLen;

    return queue;
}
