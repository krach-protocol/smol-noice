#include "nvs-cl.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"

static char TAG[] = "nvs";

esp_err_t writeByKey(char* key, char* data,char* namespace);
esp_err_t readByKey(char* key, char** data,char* namespace);
esp_err_t readByKeyBin(char* key, uint8_t** data ,uint8_t* len,char* namespace);


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
    return err;
}


esp_err_t sn_getPrivateKey(uint8_t** privateKey, uint8_t* keyLen){
    return readByKeyBin("privateKey",privateKey,keyLen,"certs");
}

esp_err_t sn_getClientCert(uint8_t** clientCert, uint8_t* certLen){
   return readByKeyBin("clientCert",clientCert,certLen,"certs");
}

esp_err_t sn_getRootCert(uint8_t** rootCert, uint8_t* certLen){
    return readByKeyBin("rootCert",rootCert,certLen,"certs");
}

esp_err_t setWifiPassword(char* wifiPassword){
    return writeByKey("wifiPassword",wifiPassword,"deviceData");
}

esp_err_t getWifiPassword(char** wifiPassword){
     return readByKey("wifiPassword",wifiPassword,"deviceData");
}

esp_err_t setWifiSSID(char* ssid){
        return writeByKey("ssid",ssid,"deviceData");
}


esp_err_t getWifiSSID(char** ssid){
     return readByKey("ssid",ssid,"deviceData");
}






esp_err_t writeByKey(char* key, char* data, char* namespace){
    esp_err_t err = ESP_OK;
    nvs_handle_t dataHandle;
    if((err = nvs_open(namespace, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",namespace,esp_err_to_name(err));
        return ESP_FAIL; 
    }
    
    if((err = nvs_set_str(dataHandle,key, data)) != ESP_OK){
        ESP_LOGE(TAG,"Error storing data namespace: %s\nErr:%s\n",key,esp_err_to_name(err));
        return ESP_FAIL; 
    }

    if((err = nvs_commit(dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error commiting changes");
        return ESP_FAIL; 
    }
     
    nvs_close(dataHandle);

    return ESP_OK;
}

esp_err_t readByKey(char* key, char** data,char* namespace){
     nvs_handle_t dataHandle;
    size_t requiredSize;
    esp_err_t err;
    
    if((err = nvs_open(namespace, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",namespace,esp_err_to_name(err));
        return ESP_FAIL; 
    }


    err = nvs_get_str(dataHandle, key, NULL, &requiredSize);
    if(err == ESP_ERR_NVS_NOT_FOUND) return err;
   
    requiredSize++; //increment by one for String terminator
   
    *data = (char*)malloc(requiredSize);
    err = nvs_get_str(dataHandle, key, *data, &requiredSize);
    (*data)[requiredSize] = '\0';

    nvs_close(dataHandle);

    return err;
}

esp_err_t readByKeyBin(char* key, uint8_t** data, uint8_t* len,char* namespace){
    nvs_handle_t dataHandle;
    size_t requiredSize;
    esp_err_t err;
    
    if((err = nvs_open(namespace, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",namespace,esp_err_to_name(err));
        return ESP_FAIL; 
    }

    err = nvs_get_blob(dataHandle, key, NULL, &requiredSize);
    if(err == ESP_ERR_NVS_NOT_FOUND) return err;
   
   
    *data = (uint8_t*)malloc(requiredSize);
    err = nvs_get_blob(dataHandle, key, *data, &requiredSize);

    nvs_close(dataHandle);

    return err;
}