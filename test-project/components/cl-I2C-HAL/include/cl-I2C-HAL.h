
#ifndef CL_I2C_HAL_H
#define CL_I2C_HAL_H

#include "esp_err.h"

typedef esp_err_t (*init_ptr)(void);

extern init_ptr clI2Cinit;
esp_err_t clI2Cdeinit();
esp_err_t clI2Csend(uint8_t address, uint8_t reg, uint8_t data);
esp_err_t clI2Cread(uint8_t , uint8_t , uint8_t*);

#endif