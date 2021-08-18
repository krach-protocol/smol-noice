#ifndef __DEVICE_DATA_CL_H__
#define __DEVICE_DATA_CL_H__

#include "esp_err.h"




esp_err_t initDeviceData();

esp_err_t getClientCert(uint8_t**);
esp_err_t setClientCert(const uint8_t*);

esp_err_t getClientPrivateKey(uint8_t**);
esp_err_t setClientPrivateKey(const uint8_t*);

esp_err_t getRootCert(uint8_t**);
esp_err_t setRootCert(const uint8_t*);

esp_err_t getWifiPassword(char**);
esp_err_t setWifiPassword(const char*);

esp_err_t getWifiSSID(char**);
esp_err_t setWifiSSID(const char*);


void register_deviceDatacl();

#endif