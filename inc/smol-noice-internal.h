#ifndef _SMOLNOICE_INTERNAL_H_
#define _SMOLNOICE_INTERNAL_H_

#include "smol-noice.h"
#include "statemachine.h"
#include <internal.h>
#include "sn_buffer.h"

typedef struct smolNoice
{
    char* hostAddress;
    uint16_t hostPort;
    int socket;
    uint8_t *clientCert;
    uint8_t clientCertLen;
    uint8_t clientPrivateKey[32];
    sc_err_t (*certCallback)(uint8_t*,uint8_t,smolcert_t*);
    NoiseHandshakeState *handshakeState;
    NoiseCipherState *rxCipher;
    NoiseCipherState *txCipher;

    sn_buffer_t* send_buffer;
    sn_buffer_t* receive_buffer;
} smolNoice_t;

#endif