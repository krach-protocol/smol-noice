#ifdef __linux__
#include "port.h"
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h> 

#include <errno.h>




#include "sn_msg.h"
#include "../queue.h"
#include "smol-noice-internal.h"

#include <time.h>
//int nanosleep(const struct timespec *req, struct timespec *rem);


#define QUEUE_LEN 10
#define RX_BUFLEN 255



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
	
    if(inet_pton(AF_INET, smolNoice->hostAddress, &serv_addr.sin_addr)<=0) {
        printf("ERROR");
        return 1; 
    }
   
    printf("Connecting to: %s:%d\n",smolNoice->hostAddress,smolNoice->hostPort);
   if(connect(smolNoice->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("Error : Connect Failed \n");
       return 1;
    } 

    if((smolNoice->rxQueue = initQueue(QUEUE_LEN)) == NULL){
       printf(" Error : Init Queue Failed \n");   
    }
    
    smolNoice->rxQueueLock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));

    pthread_mutex_init(smolNoice->rxQueueLock, NULL);
    startTask(socketListenerTask,(void*)smolNoice);    
    return 0;
}

void* socketListenerTask(void* args){
    smolNoice_t* smolNoice = (smolNoice_t*)args;
    uint8_t bytesRead = 0;
    uint8_t rxBuffer[RX_BUFLEN];
    int16_t readResult  = 0;
    sn_msg_t* rxMsg;
    int16_t errsv;
    while(1){
        sleep_ms(10);
         readResult = recv(smolNoice->socket, rxBuffer + bytesRead, RX_BUFLEN - bytesRead,MSG_DONTWAIT);
         if(readResult < 0){
            errsv = errno;
            if(errno == 104){
                printf("Error on socket: %s\n",strerror(errno));
                smolNoice->handShakeStep = ERROR;
            }
         } else if(readResult > 0){
             bytesRead += readResult;
             
            pthread_mutex_lock(smolNoice->rxQueueLock);
            addToQueue(smolNoice->rxQueue,rxBuffer,bytesRead);
            pthread_mutex_unlock(smolNoice->rxQueueLock);
             
             bytesRead = 0;
         } 
    } 
}

void sendOverNetwork(smolNoice_t *smolNoice,sn_msg_t* msg){
    size_t sentBytes = 0;
    sentBytes = send(smolNoice->socket, msg->msgBuf , msg->msgLen , 0 ); 
    free(msg->msgBuf);
}

uint8_t messageFromNetwork(smolNoice_t* smolNoice,sn_msg_t* msg){
    sn_msg_t* data = NULL;
    uint8_t ret = 0;
    pthread_mutex_lock(smolNoice->rxQueueLock);

    if(messageInQueue(smolNoice->rxQueue) == DATA_AVAILIBLE){
        getMessageFromQueue(smolNoice->rxQueue,&data); //TODO: Error handling
        msg->msgLen = data->msgLen;

        msg->msgBuf = (uint8_t*)calloc(1,msg->msgLen);
        memcpy(msg->msgBuf,data->msgBuf,msg->msgLen);

        free(data->msgBuf);
        free(data);
        ret = 1;
    }
     pthread_mutex_unlock(smolNoice->rxQueueLock);

    return ret;
}

 void sleep_ms(uint16_t waitms){
   
    struct timespec ts={0},rem;
    ts.tv_sec = 0;
    ts.tv_nsec = waitms* 1000000L;
    nanosleep(&ts, NULL);
   
 
 }


#endif