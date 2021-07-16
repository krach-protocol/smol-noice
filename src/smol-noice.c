#include "smol-noice-internal.h"

#include "statemachine.h"
#include "transport.h"

#include "sn_msg.h"

#include <internal.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

sc_err_t defaultCertCallback(uint8_t*,uint8_t,smolcert_t*);

smolNoice_t* smolNoice(void){
    smolNoice_t *smolNoice = (smolNoice_t*)malloc(sizeof(smolNoice_s));
    smolNoice->certCallback = defaultCertCallback;
    return  smolNoice;
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

sc_err_t smolNoiceSendData(smolNoice_t* smolNoice,uint8_t dataLen,uint8_t* data){
    sn_msg_t txBuffer;
    if(smolNoice->handShakeStep != DO_TRANSPORT) return SC_ERR;
    
    txBuffer.msgLen = dataLen;
    txBuffer.msgBuf = (uint8_t*)malloc(txBuffer.msgLen);
    memcpy(txBuffer.msgBuf,data,txBuffer.msgLen);
    SC_ERROR_CHECK(encryptAndSendTransport(smolNoice,&txBuffer));
    free(txBuffer.msgBuf);
    return SC_OK;
}
sc_err_t smolNoiceSetTransportCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t)){
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
