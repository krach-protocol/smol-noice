#include "deviceData-cl.h"

#include "string.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_flash_encrypt.h"
#include "esp_partition.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include "esp_log.h"
#include "esp_system.h"

#define SERVICE_KEY_LEN 32
#define DATA_NAMESPACE "deviceData"

static const char TAG[] = "DeviceData";

//Private stubs
esp_err_t writeByKey(char* key, char* data);
esp_err_t readByKey(char* key, char** data);

esp_err_t writeByKeyBin(char* key, uint8_t* data);
esp_err_t readByKeyBin(char* key, uint8_t** data);



esp_err_t initDeviceData(){
    esp_err_t err;
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_LOGI(TAG,"Error %s", esp_err_to_name(err));

    return err;
}

esp_err_t getClientCert(uint8_t** data){
    
    return readByKeyBin("clientCert",data);
}
esp_err_t setClientCert(const uint8_t* data){

    return ESP_OK;
}

esp_err_t getClientPrivateKey(uint8_t** data){

    return ESP_OK;
}
esp_err_t setClientPrivateKey(const uint8_t* data){

    return ESP_OK;
}

esp_err_t getRootCert(uint8_t** data){

    return ESP_OK;
}
esp_err_t setRootCert(const uint8_t* data){

    return ESP_OK;
}


esp_err_t getWifiPassword(char** wifiPassword){
     return readByKey("wifiPassword",wifiPassword);
}
esp_err_t setWifiPassword(const char* wifiPassword){
    return writeByKey("wifiPassword", wifiPassword);
}

esp_err_t getWifiSSID(char** ssid){
     return readByKey("ssid",ssid);
}
esp_err_t setWifiSSID(const char* ssid){
    return writeByKey("ssid", ssid);
}



esp_err_t writeByKey(char* key, char* data){
    esp_err_t err = ESP_OK;
    nvs_handle_t dataHandle;
    if((err = nvs_open(DATA_NAMESPACE, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",DATA_NAMESPACE,esp_err_to_name(err));
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

esp_err_t writeByKeyBin(char* key, char* data){
    esp_err_t err = ESP_OK;
    nvs_handle_t dataHandle;
    if((err = nvs_open(DATA_NAMESPACE, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",DATA_NAMESPACE,esp_err_to_name(err));
        return ESP_FAIL; 
    }
    
    if((err = nvs_set_blob(dataHandle,key, data)) != ESP_OK){
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



esp_err_t readByKeyBin(char* key, uint8_t** data){
    nvs_handle_t dataHandle;
    size_t requiredSize;
    esp_err_t err;
    
    if((err = nvs_open(DATA_NAMESPACE, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",DATA_NAMESPACE,esp_err_to_name(err));
        return ESP_FAIL; 
    }

    err = nvs_get_blob(dataHandle, key, NULL, &requiredSize);
    if(err == ESP_ERR_NVS_NOT_FOUND) return err;
   
    requiredSize++; //increment by one for String terminator
   
    *data = (uint8_t*)malloc(requiredSize);
    err = nvs_get_blob(dataHandle, key, *data, &requiredSize);
   

    nvs_close(dataHandle);

    return err;

}

esp_err_t readByKey(char* key, char** data){
    nvs_handle_t dataHandle;
    size_t requiredSize;
    esp_err_t err;
    
    if((err = nvs_open(DATA_NAMESPACE, NVS_READWRITE, &dataHandle)) != ESP_OK){
        ESP_LOGE(TAG,"Error opening data namespace: %s\nErr:%s\n",DATA_NAMESPACE,esp_err_to_name(err));
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




