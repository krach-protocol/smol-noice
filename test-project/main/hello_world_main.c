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


#include "nvs_flash.h"


#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"

#include <sodium.h>

#include "smol-noice.h"
#include "wifi-cl.h"
#include "cl-PortOpen.h"
#include "nvs-cl.h"



#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
EventGroupHandle_t s_wifi_event_group;

#define DEMO_WIFI_SSID "starterkitchen.de"
#define DEMO_WIFI_PW "starterkitchen2012"

esp_err_t initDeviceData();


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




sc_err_t clientCb(uint8_t* data, uint8_t len);

sc_err_t clientCb(uint8_t* data, uint8_t len){
    for(uint8_t idx = 0; idx < len; idx++){
        printf("%c",data[idx]);
    }
    return SC_OK;
}

sc_err_t remoteCertCb(uint8_t* data, uint8_t len,smolcert_t* remoteCert);

sc_err_t remoteCertCb(uint8_t* data, uint8_t len,smolcert_t* remoteCert){
    for(uint8_t idx = 0; idx < len; idx++){
        printf("%c",data[idx]);
    }
    return SC_OK;
}

void app_main(void)
{
    smolNoice_t* testConn = smolNoice();
    //const char* host = "127.0.0.1";
    char hostIP[32];
    char* hostURL = "google.de";
    uint8_t clientCertBuffer[256];
    uint8_t clientCertLen = 255;
    uint8_t clientPrivateKey[32];

    uint8_t pdx = 0;

    if( initNVS() != ESP_OK) printf("Error opening NVS\n");
    if(clPortOpeninitLock() != ESP_OK) printf("Error initialzing Lock HAL\n");

    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();

    repl_config.prompt = "cl-cli>";


    esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));

    register_NVScl();
    register_wifiCL();
    register_PortOpen();

    // start console REPL
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
    printf("Get IP for URL: %s\n", hostURL );
    dns_gethostbyname(hostURL, &ip_Addr, dns_found_cb, &hostIP);
   
    while( !DNSFound );
        

    printf("IP Adress for %s is %s",hostURL,hostIP);


    //Start application
    
    /*
    smolNoiceSetHost(testConn,host,9095);
    smolNoiceSetClientCert(testConn,clientCertBuffer,clientCertLen);
    smolNoiceSetClientPrivateKey(testConn,clientPrivateKey);

    smolNoiceSetTransportCallback(testConn,clientCb);
    smolNoiceSetRemoteCertCallback(testConn,remoteCertCb);

    smolNoiceStart(testConn);
    while(smolNoiceReadyForTransport(testConn) != SC_OK);

    while(1){
        vTaskDelay(1000/portTICK_PERIOD_MS);
        pdx++;
        printf("Sending %d \n",pdx);
        smolNoiceSendData(testConn,1,&pdx);
    }
    */

    // Currently this won't execute in a meaningful way, this is to test the build process
    /*
    smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
    sn_buffer_t clientCertBuffer;
    sn_buffer_t rootCertBuffer;
    sc_init(&clientCertBuffer,&rootCertBuffer,NULL,NULL,host,9095);
    */

    while(1){
        vTaskDelay(1000/portTICK_PERIOD_MS);
        printf("Derp\n");
    }
}

