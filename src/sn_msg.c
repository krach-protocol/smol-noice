#include "sn_msg.h"

#include <stdlib.h>

sc_err_t padBuffer(sn_buffer_t* buffer){
    uint8_t bufferLen = buffer->msgLen;
    uint8_t paddedBytes = (16-((bufferLen+16+1)%16));
    uint8_t newLen = paddedBytes+bufferLen+16+1;
    buffer->msgBuf = realloc(buffer->msgBuf,newLen);

    if(buffer->msgBuf == NULL) return SC_ERR;
    buffer->msgLen = newLen;

    for(uint8_t idx = bufferLen+1;idx>0;idx--){
        buffer->msgBuf[idx] = buffer->msgBuf[idx-1];
    }
    buffer->msgBuf[0]=paddedBytes;    


    return SC_OK;
}
sc_err_t unpadBuffer(sn_buffer_t* buffer){
    uint8_t bufferLen = buffer->msgLen;
    uint8_t paddedBytes = buffer->msgBuf[0];
     for(uint8_t idx = 0;idx<bufferLen-16;idx++){
        buffer->msgBuf[idx] = buffer->msgBuf[idx+1];
    }
    buffer->msgBuf[bufferLen-16] = '\0';


    return SC_OK;
}