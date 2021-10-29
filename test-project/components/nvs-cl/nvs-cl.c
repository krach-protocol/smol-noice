#include "nvs-cl.h"

#include "nvs.h"
#include "nvs_flash.h"


nvs_handle_t nvsHandle;

esp_err_t initNVS()
{
    esp_err_t err;
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if(err != ESP_OK) return err;

     err = nvs_open("storage", NVS_READWRITE, &nvsHandle);
    if(err != ESP_OK) return err;

    return err;
}



esp_err_t sn_getPrivateKey(uint8_t** privateKey, uint8_t* keyLen){
    size_t requiredSize;
    esp_err_t err;

    err = nvs_get_blob(nvsHandle, "privateKey", NULL, &requiredSize);
    if(err == ESP_ERR_NVS_NOT_FOUND) return err;
    *keyLen = requiredSize;
   
    *privateKey = (uint8_t*)malloc(requiredSize);
    err = nvs_get_blob(nvsHandle, "privateKey", *privateKey, &requiredSize);

    return err;
}


esp_err_t sn_getClientCert(uint8_t** clientCert, uint8_t* certLen){
    size_t requiredSize;
    esp_err_t err;

    err = nvs_get_blob(nvsHandle, "clientCert", NULL, &requiredSize);
    if(err == ESP_ERR_NVS_NOT_FOUND) return err;
    *certLen = requiredSize;

    *clientCert = (uint8_t*)malloc(requiredSize);
    err = nvs_get_blob(nvsHandle, "clientCert", *clientCert, &requiredSize);

    return err;
}

esp_err_t sn_getRootCert(uint8_t** rootCert, uint8_t* certLen){
    size_t requiredSize;
    esp_err_t err;

    err = nvs_get_blob(nvsHandle, "rootCert", NULL, &requiredSize);
    if(err == ESP_ERR_NVS_NOT_FOUND) return err;
    *certLen = requiredSize; 


    *rootCert = (uint8_t*)malloc(requiredSize);
    err = nvs_get_blob(nvsHandle, "rootCert", *rootCert, &requiredSize);


    return err;
}


