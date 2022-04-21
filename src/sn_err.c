#include "sn_err.h"
#include <stdio.h>


sn_err_t printNoiseErr(int noiseErr){
    char errBuf[32];

    if(noiseErr != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SN_ERR;
    }

    return SN_OK;
}
