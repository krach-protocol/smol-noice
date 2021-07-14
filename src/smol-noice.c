#include "smol-noice.h"

#include <internal.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

typedef sc_err_t (*dataFunction)(uint8_t,uint8_t*);

typedef struct smolNoice
{
    char* hostAddress;
    uint16_t hostPort;
    uint8_t *clientCert;
    uint8_t *rootCert;
    dataFunction certCallback;
    dataFunction transportCallback;
    NoiseHandshakeState handshake;
    NoiseCipherState rxCipher;
    NoiseCipherState txCipher;
} smolNoice_s,smolNoice_t;

smolNoice_t* smolNoice(void){
    return  (smolNoice_t*)malloc(sizeof(smolNoice_s));

}
sc_err_t smolNoiceSetHost(smolNoice_t* smolNoice, char* hostAddress,uint16_t hostPort){
    smolNoice->hostPort = hostPort;
    if(strcpy(smolNoice->hostAddress,hostAddress) == NULL) return SC_ERR;

    return SC_OK;
}

sc_err_t smolNoiceSetClientCert(smolNoice_t* smolNoice, uint8_t* clientCert){

    return SC_OK;
}
sc_err_t smolNoiceSetHostCert(smolNoice_t* smolNoice, uint8_t* hostCert){

    return SC_OK;
}

sc_err_t smolNoiceSendData(smolNoice_t* smolNoice,uint8_t dataLen,uint8_t* data){

    return SC_OK;
}
sc_err_t smolNoiceSetTransportCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t,uint8_t*)){

    return SC_OK;
}
sc_err_t smolNoiceSetRemoteCertCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t,uint8_t*)){

    return SC_OK;
}

sc_err_t smolNoiceDelete(smolNoice_t*);
