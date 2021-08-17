#ifndef INC_FREERTOS_H
//TODO: Find the right include switch for freeRTOS

/**
 * This smells kind of fishy, since it checks for a header not a compiler variable
 * Means this MUST be included AFTER freeRTOS headers
 * */ 
/*
#include "lwip/sockets.h"


#include "sn_queue.h"
#include "sn_msg.h"

sn_queue_err_t initQueues();
sn_queue_err_t QueueReceive(sn_msg_t *rxMsg);
sn_queue_err_t QueueTransmit(sn_msg_t *txMsg);
*/

#include "port.h"
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h> 

#include <errno.h>
#include <unistd.h>

#include "sn_msg.h"
#include "../queue.h"
#include "smol-noice-internal.h"

#include <time.h>

#define RX_BUFLEN 255

typedef enum {READ_LENGTH,READ_PAYLOAD} readState_t;

void* socketListenerTask(void*);

void startTask(void* (*workerTask)(void*),void* args){
    pthread_t tid; 
    pthread_create(&tid, NULL, workerTask, args);
}

uint8_t openSocket(smolNoice_t *smolNoice){
    struct sockaddr_in serv_addr; 
    if ((smolNoice->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("ERROR");
        return 1;	 
    }    
	
    serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(smolNoice->hostPort);
	
    if(inet_pton(AF_INET,  smolNoice->hostAddress, &serv_addr.sin_addr)<=0) {
        printf("ERROR");
        return 1; 
    }
   
    printf("Connecting to: %s:%d\n",smolNoice->hostAddress,smolNoice->hostPort);
   if(connect(smolNoice->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("Error : Connect Failed \n");
       return 1;
    } 

   
    startTask(socketListenerTask,(void*)smolNoice);    
    return 0;
}

void* socketListenerTask(void* args){
    smolNoice_t* smolNoice = (smolNoice_t*)args;
    uint8_t readOffset = 0;
    uint8_t rxBuffer[RX_BUFLEN];
    int16_t readResult  = 0;
    sn_msg_t* rxMsg;
    int16_t errsv;
    uint16_t packetLen;
    readState_t readState = READ_LENGTH;
    uint16_t readBytes=0;
    uint16_t totalPaketLength = 0;
    uint8_t lengthOffset = 0;
    while(1){

        switch(readState){
            case READ_LENGTH:
                if(smolNoice->handShakeStep != DO_TRANSPORT){
                    lengthOffset = 1;
                    readBytes = 3;
                }else{
                    lengthOffset = 0;
                    readBytes = 2;
                }

                packetLen = rxBuffer[0+lengthOffset] | (rxBuffer[1+lengthOffset] << 8);
                totalPaketLength = packetLen + 2 + lengthOffset;
                if(readOffset > (2+lengthOffset)) readState = READ_PAYLOAD;
            break;

            case READ_PAYLOAD:
                readBytes = packetLen;
               
                 if(readOffset == totalPaketLength){
                  
                    sn_buffer_t* dataBuffer = (sn_buffer_t*)calloc(1,sizeof(sn_buffer_t));
                    dataBuffer->msgLen = totalPaketLength;
                    dataBuffer->msgBuf = (uint8_t*)calloc(1,dataBuffer->msgLen);
                    memcpy(dataBuffer->msgBuf,rxBuffer,dataBuffer->msgLen);
                    
                    pthread_mutex_lock(smolNoice->rxQueueLock);
                        //addToQueue(smolNoice->rxQueue,rxBuffer,totalPaketLength);
                       
                        queue_write(smolNoice->rxQueue,dataBuffer);
                       
                    pthread_mutex_unlock(smolNoice->rxQueueLock);
                    readOffset = 0;
                    readBytes =0;
                    readState = READ_LENGTH;
                }
            
            break;
        }  

        pthread_mutex_lock(smolNoice->rxQueueLock);
        if(queue_peek(smolNoice->rxQueue) == FULL){
            pthread_mutex_unlock(smolNoice->rxQueueLock);
            printf("Rx Queue full!\n");
            continue;
        } 
        pthread_mutex_unlock(smolNoice->rxQueueLock);
        

       
        readResult = recv(smolNoice->socket, rxBuffer+readOffset, readBytes,0);
        if(readResult < 0){
            errsv = errno;
            if(errno == 104){
                printf("Error on socket: %s\n",strerror(errno));
                smolNoice->handShakeStep = ERROR;
                pthread_exit(NULL);
            }
        } 
        if(readResult == 0){
            continue;
        } 
        readOffset += readResult; //offset write pointer in rxBuffer
    } 
} 


void sendOverNetwork(smolNoice_t *smolNoice,sn_msg_t* msg){
    size_t sentBytes = 0;
    sentBytes = send(smolNoice->socket, msg->msgBuf , msg->msgLen , 0 ); 
    free(msg->msgBuf);
}

uint8_t messageFromNetwork(smolNoice_t* smolNoice,sn_msg_t* msg){
    sn_msg_t* dataBuffer = NULL;
    uint8_t ret = 0;
    pthread_mutex_lock(smolNoice->rxQueueLock);

    /*if(getMessageFromQueue(smolNoice->rxQueue,&data) == EMPTY){
        printf("[%s]Queue empty\n",smolNoice->rxQueue->queueName);
        pthread_mutex_unlock(smolNoice->rxQueueLock);
        return 0;
    }*/
    if(queue_read(smolNoice->rxQueue,&dataBuffer) != DATA_AVAILIBLE){
        //printf("[%s]Queue empty\n",smolNoice->rxQueue->queueName);
        pthread_mutex_unlock(smolNoice->rxQueueLock);
        return 0;
    }
    
    //printf("[%s] Data avilible\n",smolNoice->rxQueue->queueName);

   
    
    msg->msgLen = dataBuffer->msgLen;
    msg->msgBuf = (uint8_t*)calloc(1,msg->msgLen);
    memcpy(msg->msgBuf,dataBuffer->msgBuf,msg->msgLen);
    


    free(dataBuffer->msgBuf);
    free(dataBuffer);
    pthread_mutex_unlock(smolNoice->rxQueueLock);
       

    return 1;
}



#endif
