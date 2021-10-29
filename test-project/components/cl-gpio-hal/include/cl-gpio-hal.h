
#ifndef CL_GPIO_HAL_H
#define CL_GPIO_HAL_H

#define LOCK_1 GPIO_NUM_18
#define LOCK_2 GPIO_NUM_17
#define LOCK_19 GPIO_NUM_21
#define LOCK_20 GPIO_NUM_19

#include <inttypes.h>
#include "driver/gpio.h"

esp_err_t clGpioInitBulkCheck();
uint32_t clGpioGetAuxState();

esp_err_t clGpioInitLockPins();
esp_err_t clGpioSetPinState(uint8_t,uint8_t);


#endif