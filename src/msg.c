#include "msg.h"
#include <stdlib.h>
#include <string.h>

sc_err_t appendData(sc_msg_t* msg, uint8_t* data, size_t len){
    size_t oldSize = msg->len;
    size_t newSize = oldSize + len;
    if(realloc(msg->data,newSize) == NULL) return SC_ERR;
    
    return SC_OK;
}
sc_err_t getMsgLen(sc_msg_t* msg, size_t *len){
    len = &msg->len;

    return SC_OK;
}
sc_err_t getMsg(sc_msg_t* msg, uint8_t* data, size_t len){
    if(len < msg->len) return SC_ERR;
    memcpy(data,msg->data,msg->len);

    return SC_OK;
}

sc_err_t freeMsg(sc_msg_t* msg){
    free(msg->data);
    free(msg);

    return SC_OK;
}