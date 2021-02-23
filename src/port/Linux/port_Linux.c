#ifdef __linux__
#include "port.h"
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <arpa/inet.h> 

#include <pthread.h> 

#include "sn_msg.h"
#include "queue.h"

queue_t *rxQueue;
int sock;
void initQueue(void);


void startTask(void* (*workerTask)(void*),void* args){
    pthread_t tid; 
    pthread_create(&tid, NULL, workerTask, args);
}

void initQueue(void){
    rxQueue = (queue_t*)malloc(sizeof(queue_t));
    rxQueue->dataSize = sizeof(sn_msg_t);
    rxQueue->queueIdx=0;
    rxQueue->queueLen=QUEUE_LEN;

}

uint8_t openSocket(char* addr,uint8_t port){
    struct sockaddr_in serv_addr; 
    printf("Open socket\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) return 0;	 
	
    serv_addr.sin_family = AF_INET; 
	//serv_addr.sin_port = htons(port);
	serv_addr.sin_port = htons(9095);

    printf("Covnert address\n");
    //if(inet_pton(AF_INET, addr, &serv_addr.sin_addr)<=0) return 0; 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) return 0; 

    
    printf("Connect\n");
   if( connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    } 
    printf("\nConnect ok\n");



    return 0;
}

void sendOverNetwork(sn_msg_t* msg){
    send(sock , msg->msgBuf , msg->msgLen , 0 ); 
}

uint8_t messageFromNetwork(sn_msg_t* msg){
    void* data = NULL;
    if(messageInQueue(rxQueue)){
        getMessageFromQueue(rxQueue,data); //TODO: Error handling
        memcpy((void*)msg,data,rxQueue->dataSize);
        free(data);
    }

    return 0;
}


#endif