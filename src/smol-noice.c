#include "smol-noice-internal.h"

#include "statemachine.h"
#include "transport.h"

#include "sn_msg.h"

#include <internal.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define QUEUE_LEN 32

sc_err_t defaultCertCallback(uint8_t*,uint8_t,smolcert_t*);

smolNoice_t* smolNoice(void){
    smolNoice_t *smolNoice = (smolNoice_t*)calloc(1,sizeof(smolNoice_s));
    smolNoice->certCallback = defaultCertCallback;

    if((smolNoice->rxQueue = initQueue(QUEUE_LEN)) == NULL){
       printf(" Error : Init Queue Failed \n");   
    }
    smolNoice->rxQueueLock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(smolNoice->rxQueueLock, NULL);

    if((smolNoice->txQueue = initQueue(QUEUE_LEN)) == NULL){
       printf(" Error : Init Queue Failed \n");   
    }
    smolNoice->txQueue->queueName = strdup("TxQueue");
    smolNoice->rxQueue->queueName = strdup("RxQueue");
    smolNoice->txQueueLock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(smolNoice->txQueueLock, NULL);

    return smolNoice;
}

sc_err_t smolNoiceStart(smolNoice_t* smolNoice){
    sc_err_t err = SC_OK;

    SC_ERROR_CHECK(sc_init(smolNoice));

    return SC_OK;
}

sc_err_t smolNoiceSetHost(smolNoice_t* smolNoice,const char* hostAddress,uint16_t hostPort){
    smolNoice->hostPort = hostPort;
    smolNoice->hostAddress = strdup(hostAddress);

    return SC_OK;
}

sc_err_t smolNoiceSetClientCert(smolNoice_t* smolNoice, uint8_t* clientCert, uint8_t clientCertLen){
    if(clientCert == NULL) return SC_ERR;
    
    smolNoice->clientCert = clientCert;
    smolNoice->clientCertLen = clientCertLen;
    return SC_OK;
}

sc_err_t smolNoiceSetClientPrivateKey(smolNoice_t* smolNoice,uint8_t* privateKey){
    memcpy(smolNoice->clientPrivateKey,privateKey,32);

    return SC_OK;
}

sc_err_t smolNoiceSendData(smolNoice_t* smolNoice,uint8_t dataLen,uint8_t* data){
    if(smolNoice->handShakeStep != DO_TRANSPORT) return SC_ERR;
    
    sn_buffer_t *dataBuffer = (sn_buffer_t*)calloc(1,sizeof(sn_buffer_t));
    dataBuffer->msgLen = dataLen;
    dataBuffer->msgBuf = (uint8_t*)calloc(1,dataBuffer->msgLen);
    memcpy(dataBuffer->msgBuf,data,dataBuffer->msgLen);
  
    pthread_mutex_lock(smolNoice->txQueueLock);
    if(queue_peek(smolNoice->txQueue) == FULL){
        //printf("Tx queue full!\n");
        pthread_mutex_unlock(smolNoice->txQueueLock);
        return SC_ERR;
    }
    queue_write(smolNoice->txQueue,dataBuffer);
    pthread_mutex_unlock(smolNoice->txQueueLock);

    return SC_OK;
}
sc_err_t smolNoiceSetTransportCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint16_t)){
    if(dataCb == NULL) return SC_ERR;
    smolNoice->transportCallback = dataCb;

    return SC_OK;
}
sc_err_t smolNoiceSetRemoteCertCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t,smolcert_t*)){
    if(dataCb == NULL) return SC_ERR;
    smolNoice->certCallback = dataCb;
    return SC_OK;
}

sc_err_t smolNoiceDelete(smolNoice_t*);

sc_err_t smolNoiceReadyForTransport(smolNoice_t* smolNoice){
    if(smolNoice->handShakeStep != DO_TRANSPORT) return SC_ERR;

    return SC_OK;
}

sc_err_t defaultCertCallback(uint8_t* rawCert,uint8_t rawCertlen,smolcert_t* cert){
    printf("Got remote cert with length: %d\n",rawCertlen);

    return SC_OK;
}
