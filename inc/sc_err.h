#ifndef _SC_ERR_H_
#define _SC_ERR_H_

typedef enum errorType {SC_OK=0,SC_ERR=1,SC_PAKET_ERR} sc_err_t;

#define SC_ERROR_CHECK(error) \
    if(error != SC_OK) return SC_ERR;

#define STATE_ERROR_CHECK(error) \
    if(error != SC_OK){ \
        currentStep = ERROR; \
        continue; \
    } 

#endif