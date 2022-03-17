#include "transport.h"
#include "port.h"
#include "smol-noice-internal.h"
#include "sn_err.h"
#include "sn_buffer.h"
#include <stdio.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <string.h>

/* This simply sends a complete buffer to the socket. No length prefixing or anything, but it ensures the
   the complete buffer is written */
sn_err_t sn_send_buffer(size_t socket, sn_buffer_t* buf) {
    size_t sent_bytes = 0;
    while(sent_bytes < buf->len) {
        size_t n = send(socket, buf->idx + sent_bytes, buf->len - sent_bytes, 0);
        if(n < 0) {
            return SN_NET_ERR;
        }
        sent_bytes += n;
    }
    return SC_OK;
}

sn_err_t sn_read_from_socket(size_t socket, sn_buffer_t* buf, size_t expected_length) {
    sn_buffer_ensure_cap(buf, expected_length);
    size_t bytes_read = 0;
    while(bytes_read < expected_length) {
        size_t n = recv(socket, buf->idx + bytes_read, expected_length - bytes_read, 0);
        if(n < 0) {
            return SN_NET_ERR;
        }
        bytes_read += n;
    }
    return SC_OK;
}


sc_err_t encryptAndSendTransport(smolNoice_t* smolNoice,sn_buffer_t* paket){
    NoiseBuffer txBuffer;

    if(smolNoice->handShakeStep != DO_TRANSPORT) return SC_ERR;
    //printf("Padding... \n");
    //printHex(paket->msgBuf,paket->msgLen);
   
    SC_ERROR_CHECK(padBuffer(paket));
    //printf("Encrypting... \n");
    //printHex(paket->msgBuf,paket->msgLen);


    noise_buffer_set_inout(txBuffer, paket->msgBuf, paket->msgLen-16, paket->msgLen);
    NOISE_ERROR_CHECK(noise_cipherstate_encrypt(smolNoice->txCipher,&txBuffer));
    
    //TODO: wrap pack and unpack in dedicated functions
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
    //printf("Decrypting message with length: %d \n",paket->msgLen);
    //printHex(paket->msgBuf,paket->msgLen);
    //NOISE_ERROR_CHECK(noise_cipherstate_decrypt(smolNoice->rxCipher,&rxBuffer));
    if(noise_cipherstate_decrypt(smolNoice->rxCipher,&rxBuffer) != NOISE_ERROR_NONE){
        
        return SC_ERR;
    }
    paket->msgBuf +=2;
    SC_ERROR_CHECK(unpadBuffer(paket));
    return SC_OK;
}

