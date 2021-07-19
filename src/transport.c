#include "transport.h"
#include "port.h"
#include "smol-noice-internal.h"
#include "sc_err.h"
#include <stdio.h>

#include <stdlib.h>
#include <string.h>


sc_err_t encryptAndSendTransport(smolNoice_t* smolNoice,sn_buffer_t* paket){
    NoiseBuffer txBuffer;

    if(smolNoice->handShakeStep != DO_TRANSPORT) return SC_ERR;
   
    SC_ERROR_CHECK(padBuffer(paket));


    noise_buffer_set_inout(txBuffer, paket->msgBuf, paket->msgLen-16, paket->msgLen);
    NOISE_ERROR_CHECK(noise_cipherstate_encrypt(smolNoice->txCipher,&txBuffer));
    
    sn_msg_t rawPacket;
    rawPacket.msgLen = paket->msgLen+2;
    rawPacket.msgBuf = (uint8_t*)calloc(1,rawPacket.msgLen);
    uint8_t *writePtr = rawPacket.msgBuf;

    *writePtr = ((rawPacket.msgLen-2)&0x00FF);
    writePtr++;
    *writePtr = ((rawPacket.msgLen-2)&0xFF00)>>8;
    writePtr++;

    memcpy(writePtr,paket->msgBuf,paket->msgLen);
   
    sendOverNetwork(smolNoice,&rawPacket);

    return SC_OK;
}

sc_err_t decryptTransport(smolNoice_t* smolNoice,sn_buffer_t* paket){
    NoiseBuffer rxBuffer;

    //sn_msg_t unpackedNetworkPaket;
    //unpackedNetworkPaket.msgLen = (uint16_t)paket->msgBuf[0];
    //printf("Got paket length %d",unpackedNetworkPaket.msgLen);
    //unpackedNetworkPaket.msgBuf = (uint8_t*)malloc(unpackedNetworkPaket.msgLen);
    //memcpy(unpackedNetworkPaket.msgBuf,paket->msgBuf+2,unpackedNetworkPaket.msgLen);

    noise_buffer_set_inout(rxBuffer,paket->msgBuf+2,paket->msgLen-2,paket->msgLen-2);
    NOISE_ERROR_CHECK(noise_cipherstate_decrypt(smolNoice->rxCipher,&rxBuffer));
    paket->msgBuf +=2;
    SC_ERROR_CHECK(unpadBuffer(paket));
    return SC_OK;
}

