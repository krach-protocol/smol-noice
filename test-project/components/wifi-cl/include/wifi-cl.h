#ifndef __WIFI_CL_H__
#define __WIFI_CL_H__

#include "esp_wifi.h"
#include "esp_event.h"
#include "freertos/event_groups.h"
#include "esp_err.h"


#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

typedef void (*WifiInit_ptr)(void);
//extern WifiInit_ptr clInitWifi;

wifi_config_t clWifiGetCredentials(void);
esp_err_t clWifiSetCredentials(const char*,const char*);
//EventGroupHandle_t connectionEventGroup;
EventGroupHandle_t s_wifi_event_group;

/*
esp_err_t startWifiCL(void);
int stopWifiCL(void);
*/
void register_wifiCL(void);


void wifi_init_sta();

#endif