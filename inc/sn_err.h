#ifndef _SN_ERR_H_
#define _SN_ERR_H_

#include <noise/protocol.h>


typedef enum errorType {SC_OK=0,SC_ERR=1,SC_PAKET_ERR=2, SN_NET_ERR=10} sc_err_t, sn_err_t;

#define SC_ERROR_CHECK(error) \
    if(error != SC_OK) return SC_ERR;

#define SN_ERROR_CHECK(error) \
    if(error != SC_OK) return error;

#define STATE_ERROR_CHECK(error) \
    if(error != SC_OK){ \
         taskData->handShakeStep = ERROR; \
        continue; \
    } 
sc_err_t printNoiseErr(int);
#define NOISE_ERROR_CHECK(error) \
    if(printNoiseErr(error) != SC_OK) return SC_ERR;



#endif