#include "cl-PortOpen.h"
#include "cl-MCP23008-HAL.h"
#include "cl-gpio-hal.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"


#include <inttypes.h>

#define LOCK_DELAY_MS 300
#define UPPER_EXPANDER_ADDR 0x20
#define LOWER_EXPANDER_ADDR 0x21

esp_err_t openBulk(uint8_t portNum);

open_ptr clPortOpenOpen = openBulk;

esp_err_t clPortOpeninitLock(){
    esp_err_t err;

    err = clGpioInitLockPins();
    if(err != ESP_OK){
            return err;
    }

    err = clMCPnit(UPPER_EXPANDER_ADDR);
    if(err != ESP_OK){
            return err;
    }

    err = clMCPnit(LOWER_EXPANDER_ADDR);
    if(err != ESP_OK){
            return err;
    }

    return err;
}

esp_err_t openBulk(uint8_t portNum){
    esp_err_t err;
    if(portNum > 20) return ESP_FAIL;
    
    if(portNum > 10){
        portNum = 21-(portNum-10); //compensate for wrong enclosure markings
    }
    switch(portNum){
        case 1:
    
        err = clGpioSetPinState(LOCK_1,1);
        if(err != ESP_OK){
            break;
        }

        vTaskDelay(LOCK_DELAY_MS / portTICK_PERIOD_MS);

        err = clGpioSetPinState(LOCK_1,0);
    
        break;
        case 2:

        err = clGpioSetPinState(LOCK_2,1);
        if(err != ESP_OK){
            break;
        }

        vTaskDelay(LOCK_DELAY_MS / portTICK_PERIOD_MS);

        err = clGpioSetPinState(LOCK_2,0);
        break;

        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:

        err = clMCPwritePort(UPPER_EXPANDER_ADDR, 0x00 | (1<<(portNum-3)) );
        if(err != ESP_OK){
            break;
        }

        vTaskDelay(LOCK_DELAY_MS / portTICK_PERIOD_MS);

        err = clMCPwritePort(UPPER_EXPANDER_ADDR, 0x00 );
        break;

        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:

        err = clMCPwritePort(LOWER_EXPANDER_ADDR, (1<<(portNum-11)) );
        if(err != ESP_OK){
            break;
        }

        vTaskDelay(LOCK_DELAY_MS / portTICK_PERIOD_MS);

        err = clMCPwritePort(LOWER_EXPANDER_ADDR, 0x00 );
        break;

        break;

        case 19:
        // IO21
        err = clGpioSetPinState(LOCK_19,1);
        if(err != ESP_OK){
            break;
        }

        vTaskDelay(LOCK_DELAY_MS / portTICK_PERIOD_MS);

        err = clGpioSetPinState(LOCK_19,0);
        break;
        case 20:
        // IO25
        err = clGpioSetPinState(LOCK_20,1);
        if(err != ESP_OK){
            break;
        }

        vTaskDelay(LOCK_DELAY_MS / portTICK_PERIOD_MS);

        err = clGpioSetPinState(LOCK_20,0);
        break;

        default:
            err = ESP_FAIL;
        break;
    }

    return err;
}


