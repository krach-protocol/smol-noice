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
    uint8_t *clientCert;
    uint8_t clientCertLen;
    sc_err_t (*certCallback)(uint8_t*,uint8_t,smolcert_t*);
    sc_err_t (*transportCallback)(uint8_t*,uint8_t);
    NoiseHandshakeState *handshakeState;
    handshakeStep handShakeStep;
    NoiseCipherState *rxCipher;
    NoiseCipherState *txCipher;
} smolNoice_s,smolNoice_t;

#endif