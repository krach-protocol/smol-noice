
#ifndef CL_MCP23008_HAL_H
#define CL_MCP23008_HAL_H

#include "esp_err.h"
#include "cl-MCP23008-HAL.h"
#include "cl-I2C-HAL.h"


esp_err_t clMCPnit(uint8_t addr);

esp_err_t clMCPwritePort(uint8_t addr, uint8_t val);

esp_err_t clMCPsetPortDirection(uint8_t addr, uint8_t dir);

esp_err_t clMCPsetDefaultValue(uint8_t addr,uint8_t val);

#endif