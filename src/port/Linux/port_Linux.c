#ifdef __linux__
#include "port.h"
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h> 

#include <pthread.h> 




#include "sn_msg.h"
#include "queue.h"

#include <time.h>
//int nanosleep(const struct timespec *req, struct timespec *rem);


#define QUEUE_LEN 10
queue_t *rxQueue;
int sock;


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
       printf(" Error : Connect Failed \n");
       return 1;
    } 
    printf("Connect ok\n");

    printf("initializing rx Queue\n");
    if((rxQueue = initQueue(QUEUE_LEN)) == NULL){
       printf(" Error : Init Queue Failed \n");   
    }
    printf("Init Queue ok\n");

    return 0;
}

void sendOverNetwork(sn_msg_t* msg){
    size_t sentBytes = 0;
    sentBytes = send(sock , msg->msgBuf , msg->msgLen , 0 ); 
    printf("Got message with length: %d\n",*((uint16_t*)msg->msgBuf));
    printf("Sent %ld of %d bytes\n",sentBytes,msg->msgLen);
}

uint8_t messageFromNetwork(sn_msg_t* msg){
    void* data = NULL;
    uint8_t ret = 0;
    if(messageInQueue(rxQueue)){
        getMessageFromQueue(rxQueue,data); //TODO: Error handling
        memcpy((void*)msg,data,rxQueue->dataSize);
        free(data);
        ret = 1;
    }

    return ret;
}

 void sleep_ms(uint16_t waitms){
   
    struct timespec ts,rem;
    ts.tv_sec = 0;
    ts.tv_nsec = waitms* 1000000L;
    nanosleep(&ts, &rem);
   
 
 }


#endif