
#ifndef CL_PORT_OPEN_H
#define CL_PORT_OPEN_H

#include <inttypes.h>
#include "esp_err.h"
typedef esp_err_t (*open_ptr)(uint8_t);

extern open_ptr clPortOpenOpen;
esp_err_t clPortOpeninitLock();

void register_PortOpen();

#endif