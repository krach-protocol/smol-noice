#include "sn_msg.h"

#include <stdlib.h>
#include <string.h>

sc_err_t padBuffer(sn_buffer_t* buffer){
    uint8_t bufferLen = buffer->msgLen;
    uint8_t paddedBytes = (16-((bufferLen+16+1)%16));
    uint8_t newLen = paddedBytes+bufferLen+16+1;
    uint8_t *newBuffer = (uint8_t*)calloc(1,newLen);

    if(newBuffer == NULL) return SC_ERR;
    buffer->msgLen = newLen;

    for(uint8_t idx = 0;idx<bufferLen;idx++){
        newBuffer[idx+1] = buffer->msgBuf[idx];
    }
    newBuffer[0]=paddedBytes;    

    free(buffer->msgBuf);
    buffer->msgBuf = newBuffer;

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