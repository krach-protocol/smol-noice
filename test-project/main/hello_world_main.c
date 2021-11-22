/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_console.h"
#include "esp_err.h"

#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"


#include "nvs_flash.h"


#include <sodium.h>

#include "smol-noice.h"
#include "wifi-cl.h"
#include "cl-PortOpen.h"
#include "nvs-cl.h"



#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
EventGroupHandle_t s_wifi_event_group;

#define HOST_URL "citynode.ingress.connctd.io"


sc_err_t clientCb(uint8_t* data, uint8_t len);
sc_err_t remoteCertCb(uint8_t* data, uint8_t len,smolcert_t* remoteCert);

void transportCallback(uint8_t* data){
    uint8_t parsedPort = 0;
    clPortOpenOpen(parsedPort);
}

bool DNSFound = false;
void dns_found_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg)
{
    ip_addr_t ip_Addr;
    IP_ADDR4( &ip_Addr, 0,0,0,0 );
     if(ipaddr != NULL)
     {
        ip_Addr = *ipaddr;
        sprintf((char*)callback_arg,"%i.%i.%i.%i", 
        ip4_addr1(&ipaddr->u_addr.ip4), 
        ip4_addr2(&ipaddr->u_addr.ip4), 
        ip4_addr3(&ipaddr->u_addr.ip4), 
        ip4_addr4(&ipaddr->u_addr.ip4));
        DNSFound = true;
    } 
    vTaskDelay(200/portTICK_PERIOD_MS);
}


sc_err_t clientCb(uint8_t* data, uint8_t len){
    for(uint8_t idx = 0; idx < len; idx++){
        printf("%c",data[idx]);
    }
    return SC_OK;
}


sc_err_t remoteCertCb(uint8_t* data, uint8_t len,smolcert_t* remoteCert){
    for(uint8_t idx = 0; idx < len; idx++){
        printf("%c",data[idx]);
    }
    return SC_OK;
}

void app_main(void)
{
    smolNoice_t* testConn = smolNoice();
    char hostIP[32];
    char* hostURL = HOST_URL;
    uint16_t hostPort = 48032;
    uint8_t* clientCertBuffer = NULL;
    uint8_t clientCertLen = 0;
    uint8_t* clientPrivateKeyBuffer  = NULL;
    uint8_t clientPrivateKeyLen = 0;
    uint8_t *rootCertbuffer  = NULL;
    uint8_t rootCertLen = 0;
    esp_err_t err;

    uint8_t pdx = 0;

    if( (err = initNVS()) != ESP_OK) ESP_LOGE("main","Error opening NVS: %s\n",esp_err_to_name(err));
    if( (err = clPortOpeninitLock()) != ESP_OK) ESP_LOGE("main","Error initialzing Lock HAL: %s\n",esp_err_to_name(err));

    //CLI Setup
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    repl_config.prompt = "cl-cli>";
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));
    register_NVScl();
    register_wifiCL();
    register_PortOpen();
    ESP_ERROR_CHECK(esp_console_start_repl(repl));   
    
    //WIFI Setup
    wifi_init_sta();
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);
     if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI("main","connected to wifi\n\r");
     }

    //DNS resolve 
    ip_addr_t ip_Addr;
    IP_ADDR4( &ip_Addr, 0,0,0,0 );
    ESP_LOGI("main","Get IP for URL: %s\n", hostURL );
    while( !DNSFound ){
        dns_gethostbyname(hostURL, &ip_Addr, dns_found_cb, &hostIP);
    }
    ESP_LOGI("main","IP Adress for %s is %s",hostURL,hostIP);


   
    //Get Certs from NVS
    sn_getClientCert(&clientCertBuffer,&clientCertLen);
    sn_getPrivateKey(&clientPrivateKeyBuffer,&clientPrivateKeyLen);
    sn_getRootCert(&rootCertbuffer,&rootCertLen);

    //Setup smol-noice
    smolNoiceSetHost(testConn,hostIP,hostPort);
    smolNoiceSetClientCert(testConn,clientCertBuffer,clientCertLen);
    smolNoiceSetClientPrivateKey(testConn,clientPrivateKeyBuffer);

    smolNoiceSetTransportCallback(testConn,clientCb);
    smolNoiceSetRemoteCertCallback(testConn,remoteCertCb);

     //Start application
    smolNoiceStart(testConn);
    while(smolNoiceReadyForTransport(testConn) != SC_OK);

    
    while(1){
        vTaskDelay(1000/portTICK_PERIOD_MS);
        pdx++;
        ESP_LOGI("main","Sending %d \n",pdx);
        smolNoiceSendData(testConn,1,&pdx);
    }
}

