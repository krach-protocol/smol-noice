#include "cl-MCP23008-HAL.h"
#include "cl-I2C-HAL.h"

#include "esp_err.h"



esp_err_t clMCPnit(uint8_t addr){
    esp_err_t err;
    if((err = clI2Cinit()) != ESP_OK) return err;

    err = clMCPsetPortDirection(addr,0x00);
    
    if(err != ESP_OK){
        return err;
    }
    err = clMCPwritePort(addr,0x00);
    
    if(err != ESP_OK){
        return err;
    }    
    return err;
}

esp_err_t clMCPwritePort(uint8_t addr, uint8_t val){
    esp_err_t err;
    err = clI2Csend(addr,0x09,val);
    return err;
}

esp_err_t clMCPsetPortDirection(uint8_t addr, uint8_t dir){
    esp_err_t err;
    err = clI2Csend(addr,0x00,dir);
    return err;

}






