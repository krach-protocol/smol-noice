#ifdef __linux__
#include "port.h"
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h> 

#include <pthread.h> 
#include <errno.h>




#include "sn_msg.h"
#include "queue.h"

#include <time.h>
//int nanosleep(const struct timespec *req, struct timespec *rem);


#define QUEUE_LEN 10
#define RX_BUFLEN 255
queue_t *rxQueue;
int sock;
pthread_mutex_t lock;



void* socketListenerTask(void*);

void startTask(void* (*workerTask)(void*),void* args){
    pthread_t tid; 
    pthread_create(&tid, NULL, workerTask, args);
}

uint8_t openSocket(char* addr,uint16_t port){
    struct sockaddr_in serv_addr; 
    printf("Open socket\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("ERROR");
        return 1;	 
    } 
    printf("Socket ok\n");
        
	
    serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(port);
	//serv_addr.sin_port = htons(9095);

    printf("Convert address\n");
    if(inet_pton(AF_INET, addr, &serv_addr.sin_addr)<=0) {
        printf("ERROR");
        return 1; 
    }
    printf("Convert address ok\n");
    //if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) return 0; 

    
    printf("Connecting to: %s:%d\n",addr,port);
   if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("Error : Connect Failed \n");
       return 1;
    } 
    printf("Connect ok\n");

    printf("initializing rx Queue\n");
    if((rxQueue = initQueue(QUEUE_LEN)) == NULL){
       printf(" Error : Init Queue Failed \n");   
    }
    printf("Init Queue ok\n");

    pthread_mutex_init(&lock, NULL);
    startTask(socketListenerTask,(void*)rxQueue);    
    return 0;
}

void* socketListenerTask(void* args){
    queue_t* rxQueue = (queue_t*)args;
    uint8_t bytesRead = 0;
    uint8_t rxBuffer[RX_BUFLEN];
    int16_t readResult  = 0;
    sn_msg_t* rxMsg;
    int16_t errsv;
    while(1){
        sleep_ms(100);
         readResult = recv(sock, rxBuffer + bytesRead, RX_BUFLEN - bytesRead,MSG_DONTWAIT);
         if(readResult < 0){
            errsv = errno;
            //printf("Error on socket: %s\n",strerror(errno));
         } else if(readResult > 0){
             printf("Read %d bytes from socket\n",readResult);
             bytesRead += readResult;
             //Rx complete
             rxMsg = (sn_msg_t*)malloc(sizeof(sn_msg_t));
             rxMsg->msgLen = bytesRead;
             rxMsg->msgBuf = (uint8_t*)malloc(rxMsg->msgLen);
             memcpy(rxMsg->msgBuf,rxBuffer,rxMsg->msgLen);
            pthread_mutex_lock(&lock);
             addToQueue(rxQueue,rxMsg);
              pthread_mutex_unlock(&lock);
             bytesRead = 0;
         } 
    } 
}

void sendOverNetwork(sn_msg_t* msg){
    size_t sentBytes = 0;
    sentBytes = send(sock , msg->msgBuf , msg->msgLen , 0 ); 
    printf("Got message with length: %d\n",*((uint16_t*)msg->msgBuf));
    printf("Sent %ld of %d bytes\n",sentBytes,msg->msgLen);
}

uint8_t messageFromNetwork(sn_msg_t* msg){
    sn_msg_t* data = NULL;
    uint8_t ret = 0;
    pthread_mutex_lock(&lock);

    if(messageInQueue(rxQueue) == DATA_AVAILIBLE){
        getMessageFromQueue(rxQueue,&data); //TODO: Error handling
        msg->msgLen = data->msgLen;
        free(msg->msgBuf);

        msg->msgBuf = (uint8_t*)malloc(msg->msgLen);
        memcpy(msg->msgBuf,data->msgBuf,msg->msgLen);

        //free(data);
        ret = 1;
    }
     pthread_mutex_unlock(&lock);

    return ret;
}

 void sleep_ms(uint16_t waitms){
   
    struct timespec ts,rem;
    ts.tv_sec = 0;
    ts.tv_nsec = waitms* 1000000L;
    nanosleep(&ts, &rem);
   
 
 }


#endif