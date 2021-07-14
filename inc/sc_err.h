#ifndef _SC_ERR_H_
#define _SC_ERR_H_

#include <noise/protocol.h>


typedef enum errorType {SC_OK=0,SC_ERR=1,SC_PAKET_ERR} sc_err_t;

#define SC_ERROR_CHECK(error) \
    if(error != SC_OK) return SC_ERR;

#define STATE_ERROR_CHECK(error) \
    if(error != SC_OK){ \
        currentStep = ERROR; \
        continue; \
    } 
sc_err_t printNoiseErr(int);
#define NOISE_ERROR_CHECK(error) \
    if(printNoiseErr(error) != SC_OK) return SC_ERR;



#endif