#include "smol-noice-internal.h"

#include "statemachine.h"
#include "transport.h"
#include "handshake.h"

#include "sn_buffer.h"

#include <internal.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define QUEUE_LEN 32

sc_err_t defaultCertCallback(uint8_t*,uint8_t,smolcert_t*);

smolNoice_t* smolNoice(void){
    smolNoice_t *smolNoice = (smolNoice_t*)calloc(1,sizeof(smolNoice_t));
    smolNoice->certCallback = defaultCertCallback;
    size_t buffer_size = SN_MAX_FRAME_SIZE * 16 /*Max padding*/ + 16 /* MAC*/ + 1 /*padding prefix*/ + 2 /*length prefix*/;
    smolNoice->receive_buffer = sn_buffer_new(buffer_size);
    smolNoice->send_buffer = sn_buffer_new(buffer_size);
    return smolNoice;
}

uint8_t open_socket(smolNoice_t *smolNoice){
    struct sockaddr_in serv_addr; 
    if ((smolNoice->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("ERROR");
        return 1;	 
    }    
	
    serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(smolNoice->hostPort);
	
    if(inet_pton(AF_INET,  smolNoice->hostAddress, &serv_addr.sin_addr)<=0) {
        printf("ERROR");
        return 1; 
    }
   
    printf("Connecting to: %s:%d\n",smolNoice->hostAddress,smolNoice->hostPort);
   if(connect(smolNoice->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("Error : Connect Failed \n");
       return 1;
    }  
    return 0;
}

sn_err_t sn_connect(smolNoice_t* smol_noice) {
    SN_ERROR_CHECK(sn_init(smol_noice));
    if(( sn_err_t err = run_handshake(smol_noice)) != SC_OK) {
        close(smol_noice->socket);
        return err;
    }
    return SC_OK;
}

sc_err_t sn_set_host(smolNoice_t* smolNoice,const char* hostAddress,uint16_t hostPort){
    smolNoice->hostPort = hostPort;
    smolNoice->hostAddress = strdup(hostAddress);

    return SC_OK;
}

sc_err_t sn_set_client_cert(smolNoice_t* smolNoice, uint8_t* clientCert, uint8_t clientCertLen){
    if(clientCert == NULL) return SC_ERR;
    
    smolNoice->clientCert = clientCert;
    smolNoice->clientCertLen = clientCertLen;
    return SC_OK;
}

sc_err_t sn_set_client_priv_key(smolNoice_t* smolNoice,uint8_t* privateKey){
    memcpy(smolNoice->clientPrivateKey,privateKey,32);

    return SC_OK;
}

int sn_send(smolNoice_t* smol_noice, uint8_t* buf, size_t buf_len) {
    size_t send_data = 0;
    uint8_t* read_ptr = buf;

    while(send_data < buf_len) {
        size_t m = buf_len - send_data;
        if(m > SN_MAX_FRAME_SIZE) {
            m = SN_MAX_FRAME_SIZE;
        }
        sn_buffer_reset(smol_noice->send_buffer);
        smol_noice->send_buffer->idx += 3; // Enable faster padding and keep space for the length prefix
        sn_buffer_copy_into(smol_noice->send_buffer, read_ptr, m);
        sn_buffer_pad(smol_noice->send_buffer);
        read_ptr += m;
        send_data += m;
        
        NoiseBuffer txBuffer;
        sn_buffer_ensure_cap(smol_noice->send_buffer, smol_noice->send_buffer->len + 16); // Ensure we have enough space for the MAC
        noise_buffer_set_inout(txBuffer, smol_noice->send_buffer->idx, smol_noice->send_buffer->len, smol_noice->send_buffer->len+16);
        if(noise_cipherstate_encrypt(smol_noice->txCipher, &txBuffer) != NOISE_ERROR_NONE) {
            return -1;
        }
        smol_noice->send_buffer->len += 16; //We have now the MAC appended
        uint16_t pkt_len = smol_noice->send_buffer->len;
        sn_buffer_rewind(smol_noice->send_buffer);
        sn_buffer_write_uint16(smol_noice->send_buffer, pkt_len);
        sn_err_t err = sn_send_buffer(smol_noice->socket, smol_noice->send_buffer);
        if(err != SC_OK) {
            return -2;
        }
    }
    return (int)send_data;
}

int sn_recv(smolNoice_t* smol_noice, uint8_t* buf, size_t buf_len) {
    sn_buffer_reset(smol_noice->receive_buffer);
    sn_err_t err = sn_read_from_socket(smol_noice->socket, smol_noice->receive_buffer, 2); // Read the length prefix
    if(err != SC_OK) {
        return -1;
    }
    sn_buffer_rewind(smol_noice->receive_buffer);
    uint16_t pkt_len = sn_buffer_read_uint16(smol_noice->receive_buffer);
    if(buf_len < pkt_len) {
        return -2;
    }
    uint16_t read_data = 0;
    sn_buffer_reset(smol_noice->receive_buffer);
    sn_read_from_socket(smol_noice->socket, smol_noice->receive_buffer, pkt_len);
    NoiseBuffer rxBuffer;
    noise_buffer_set_inout(rxBuffer, smol_noice->receive_buffer, smol_noice->receive_buffer->len, smol_noice->receive_buffer->len);
    if(noise_cipherstate_decrypt(smolNoice->rxCipher, &rxBuffer) != NOISE_ERROR_NONE){
        return -3;
    }
    smol_noice->receive_buffer->len -= 16; //Remove the MAC at the end
    sn_buffer_unpad(smol_noice->receive_buffer);
    memcpy(buf, smol_noice->receive_buffer->idx, smol_noice->receive_buffer->len);
    return (int)smol_noice->receive_buffer->len;
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

sc_err_t sn_set_remote_cert_callback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t,smolcert_t*)){
    if(dataCb == NULL) return SC_ERR;
    smolNoice->certCallback = dataCb;
    return SC_OK;
}

sc_err_t sn_free(smolNoice_t* smol_noice) {
    sn_buffer_free(smol_noice->send_buffer);
    sn_buffer_free(smol_noice->receive_buffer);
    free(smol_noice);
}

sc_err_t smolNoiceReadyForTransport(smolNoice_t* smolNoice){
    if(smolNoice->handShakeStep != DO_TRANSPORT) return SC_ERR;

    return SC_OK;
}

sc_err_t defaultCertCallback(uint8_t* rawCert,uint8_t rawCertlen,smolcert_t* cert){
    printf("Got remote cert with length: %d\n",rawCertlen);

    return SC_OK;
}
