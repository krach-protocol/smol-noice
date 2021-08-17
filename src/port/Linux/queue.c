#include "../queue.h"
#include "sn_msg.h"

#include <stdio.h>
#include <string.h>


queue_t* initQueue(uint8_t queueLen){
    queue_t *queue = (queue_t*)calloc(1,sizeof(queue_t));
    queue->size = queueLen;
    queue->data = (sn_buffer_t**)calloc(queueLen,sizeof(sn_buffer_t*));
    
    return queue;
}

queue_err_e queue_peek(queue_t* queue){
    if(((queue->head + 1) % queue->size) == queue->tail) {
        return FULL;
    }
    return OK;
}

queue_err_e queue_read(queue_t *queue,sn_buffer_t** data){
    if (queue->tail == queue->head) {
        return EMPTY;
    }
    *data = queue->data[queue->tail];
    queue->data[queue->tail] = NULL;
    queue->tail = (queue->tail + 1) % queue->size;
    return DATA_AVAILIBLE;
}

queue_err_e queue_write(queue_t *queue, sn_buffer_t* data){
    
    if(((queue->head + 1) % queue->size) == queue->tail) {
        return FULL;
    }
    queue->data[queue->head] = data;
    queue->head = (queue->head + 1) % queue->size;
    return OK;
}



/*
queue_err_e messageInQueue(queue_t* queue){

    if(queue->elementsInQueue > 0) return DATA_AVAILIBLE;
    
    return EMPTY;
}

queue_err_e getMessageFromQueue(queue_t* queue, sn_msg_t** data){
    queue_err_e err = OK;
    printf("[%s] Get message from queue\n",queue->queueName);
    if(queue->elementsInQueue == 0)return EMPTY;

    printf("[%s] ReadIdx:%02d\t  WriteIdx: %02d\t  Messages: %02d\n",queue->queueName,queue->readIdx,queue->writeIdx,queue->elementsInQueue);
   

    *data = queue->data[queue->readIdx];
    
   
    queue->elementsInQueue--;
   if(queue->elementsInQueue > 0) queue->readIdx =  (queue->readIdx%queue->queueLen)+1; 
        
    return OK;
}
queue_err_e addToQueue(queue_t* queue,uint8_t* data, uint8_t dataLen){
    queue_err_e err = OK;

    printf("[%s] ReadIdx:%02d\t  WriteIdx: %02d\t  Messages: %02d\n",queue->queueName,queue->readIdx,queue->writeIdx,queue->elementsInQueue);
    if((((queue->writeIdx%queue->queueLen)) == queue->readIdx) && (queue->elementsInQueue != 0)){
        printf("[%s] queue full\n",queue->queueName);
        return FULL;
    } 

    
    sn_buffer_t* dataPaket = (sn_buffer_t*)calloc(1,sizeof(sn_buffer_t));
    if((dataPaket) == NULL) return NO_MEM;


    dataPaket->msgLen = dataLen;
    dataPaket->msgBuf = (uint8_t*)calloc(1,dataPaket->msgLen);
    if((dataPaket)->msgBuf == NULL)return NO_MEM;

    memcpy(dataPaket->msgBuf,data,dataPaket->msgLen);
   
    queue->data[queue->writeIdx] = dataPaket;
    queue->elementsInQueue++;
    if(queue->elementsInQueue < queue->queueLen) queue->writeIdx =  (queue->writeIdx%queue->queueLen)+1;

    return OK;
}

queue_t* initQueue(uint8_t queueLen){
    queue_t *queue = (queue_t*)calloc(1,sizeof(queue_t));
    queue->writeIdx=0;
    queue->readIdx=0;
    queue->data = (sn_msg_t**)calloc(queueLen,sizeof(sn_msg_t*));
    queue->queueLen=queueLen;
    queue->elementsInQueue = 0;

    return queue;
}*/
