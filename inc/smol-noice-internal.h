#ifndef _SMOLNOICE_INTERNAL_H_
#define _SMOLNOICE_INTERNAL_H_

#include "smol-noice.h"
#include "statemachine.h"
#include <internal.h>
#include <pthread.h>  
#include "../src/port/queue.h"

typedef struct smolNoice
{
    char* hostAddress;
    uint16_t hostPort;
    int socket;
    queue_t* rxQueue;
    pthread_mutex_t* rxQueueLock;
    queue_t* txQueue;
    pthread_mutex_t* txQueueLock;
    uint8_t *clientCert;
    uint8_t clientCertLen;
    uint8_t clientPrivateKey[32];
    sc_err_t (*certCallback)(uint8_t*,uint8_t,smolcert_t*);
    sc_err_t (*transportCallback)(uint8_t*,uint16_t);
    handshakeStep handShakeStep;
    NoiseHandshakeState *handshakeState;
    NoiseCipherState *rxCipher;
    NoiseCipherState *txCipher;
} smolNoice_s,smolNoice_t;

#endif