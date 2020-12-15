#ifndef _SC_MESSAGE_H_
#define _SC_MESSAGE_H_

#include <inttypes.h>
#include <stdlib.h>

#include "err.h"



/**
 * Struct: sc_msg_t
 * ------------------
 * Container for messages
 * 
 * len:  length of payload data
 * data: pointer payload data
 * */
typedef struct {
    size_t      len;
    uint8_t*    data;
} sc_msg_t;


/**
 * Function: appendData
 * -----------------
 * Appends data to the message struct, handles memory allocation for itself
 * 
 *  msg:    pointer to message struct
 *  data:   pointer to uint8 array which has to be appended
 *  len:    pointer to size type, contains the length of data to append
 *  return sc_err_t, SC_ERR if something went wrong else SC_OK 
 * */
sc_err_t appendData(sc_msg_t* msg, uint8_t* data, size_t len);

/**
 * Function: getMsgLen
 * -----------------
 * Extracts the length of the message struct into a size variable.
 * 
 *  msg:    pointer to message struct
 *  len:    pointer to size type, contains the length of data after use
 *  return sc_err_t, SC_ERR if something went wrong else SC_OK 
 * */
sc_err_t getMsgLen(sc_msg_t* msg, size_t *len);

/**
 * Function: getMsg
 * -----------------
 * Extracts the content of the message struct into a uint8 array.
 * Important: free data after use
 * 
 *  msg:    pointer to message struct
 *  data:   pointer to uint8 buffer, contains the data after use
 *  len:    size of allocared data buffer
 *  return sc_err_t, SC_ERR if something went wrong else SC_OK 
 * */
sc_err_t getMsg(sc_msg_t* msg, uint8_t* data, size_t len);

/**
 * Function: freeMsg
 * -----------------
 * Helperfunction to free allocated memory in a clean way
 * 
 *  msg:    pointer to message struct
 *  return sc_err_t, SC_ERR if something went wrong else SC_OK 
 * */
sc_err_t freeMsg(sc_msg_t* msg);


#endif