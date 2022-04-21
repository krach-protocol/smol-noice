#ifndef _SN_ERR_H_
#define _SN_ERR_H_

#include <noise/protocol.h>


typedef enum errorType {SN_OK=0,SN_ERR=1,SN_PAKET_ERR=2, SN_NET_ERR=10} sn_err_t;

#define SN_ERROR_CHECK(error) \
    if(error != SN_OK) return error;

sn_err_t printNoiseErr(int);
#define NOISE_ERROR_CHECK(error) \
    if(printNoiseErr(error) != SN_OK) return SN_ERR;

#endif
