#ifndef __NVS_CL_H__
#define __NVS_CL_H__

#include "esp_err.h"
#include <inttypes.h>

esp_err_t initNVS();

esp_err_t sn_getRootCert(uint8_t** rootCert,uint8_t* certLen);
esp_err_t sn_getClientCert(uint8_t** clientCert,uint8_t* certLen);
esp_err_t sn_getPrivateKey(uint8_t** privateKey,uint8_t* keyLen);

void register_NVScl();

#endif