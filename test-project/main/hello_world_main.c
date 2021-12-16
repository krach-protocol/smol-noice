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
#include "sc_packet.h"
#include "wifi-cl.h"
#include "cl-PortOpen.h"
#include "nvs-cl.h"

#include "cbor.h"

#define NVS_ERROR_CHECK(fun) if((err = fun) != ESP_OK){ESP_LOGE("main","Error reading NVS: %s",esp_err_to_name(err));}

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
EventGroupHandle_t s_wifi_event_group;

#define HOST_URL "citynode.ingress.connctd.io"

const char TAG[] = "main";
sc_err_t clientCb(uint8_t* data, uint16_t len);
sc_err_t remoteCertCb(uint8_t* data, uint8_t len,smolcert_t* remoteCert);
void parseMessage(uint8_t* data, uint16_t len);

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

static uint8_t msgBuf[1024];
static uint16_t expectedMsgLen= 0;
static uint16_t receivedLen = 0;
static bool lengthReceived = false;
static bool waitingForData = false;

sc_err_t clientCb(uint8_t* data, uint16_t len){
    size_t offset = 0;
    ESP_LOGI("smolClientCb","Got data");
    if(!lengthReceived) {
        if(len>1) {
            expectedMsgLen = readUint16(data);
            lengthReceived = true;
            waitingForData = true;
            offset = 2;
        } else {
            // Currently not supported to only partially receive the prefixed length
            // We should cancel and reestablish the connection
            return SC_ERR;
        }
    }
    if(waitingForData) {
        uint8_t* destPtr = msgBuf + receivedLen;
        uint8_t* srcPtr = data + offset;
        memcpy(destPtr, srcPtr, len - offset);
        receivedLen += (len - offset);
    }
    if(receivedLen == expectedMsgLen) {
        // Packet completely received into msgBuf
        uint16_t len = receivedLen;
        lengthReceived = false;
        waitingForData = false;
        receivedLen = 0;
        expectedMsgLen = 0;
        parseMessage(msgBuf, len);
    }
    return SC_OK;
}

typedef enum {PING,OPEN} cbor_command_t;

void parseMessage(uint8_t* data, uint16_t len) {
    CborParser parser;
    CborValue it;
    CborError err = cbor_parser_init(data, (size_t)len, 0, &parser, &it);
    ESP_LOGI("cbor:","Got message");
    if(err != CborNoError) {
        ESP_LOGE("cbor:","Error init CBOR");
        // TODO log this error, probably close connection and reconnect
        return;
    }
    if(cbor_value_is_map(&it)) {
        // If we have a map
        CborValue val;
        // Find the key 'command-name' and get a pointer to its value
        err = cbor_value_map_find_value(&it, "command-name", &val);
        if(err != CborNoError) {
            ESP_LOGE("cbor:","Error parsing CBOR map");
            // TODO log error etc.
            return;
        }


        bool isOpen = false;
        // Check that the value is actually euqal to the string 'open'
        err = cbor_value_text_string_equals(&val, "open", &isOpen);
        if(err != CborNoError) {
            // TODO log error etc.
            return;
        }
        if(isOpen) {
            ESP_LOGI("cbor:","Opening Lock");
            // TODO open lock
        }

        bool isPing = false;
        err = cbor_value_text_string_equals(&val, "ping", &isOpen);

        if(isPing){
            ESP_LOGI("cbor:","ping command");
        }
    }
    
}


sc_err_t remoteCertCb(uint8_t* data, uint8_t len,smolcert_t* remoteCert){
    printf("Remote Server Cert:\n");
    //ESP_LOG_BUFFER_HEXDUMP(TAG,data,len,ESP_LOG_INFO);
    printf("\n");
    return SC_OK;
}

uint8_t clientCertBuffer[] = {
  0x87, 0x02, 0x73, 0x63, 0x69, 0x74, 0x79, 0x6e, 0x6f, 0x64, 0x65, 0x2d,
  0x73, 0x65, 0x6e, 0x73, 0x65, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x82, 0x1a,
  0x61, 0x79, 0x6c, 0x47, 0x00, 0x60, 0x58, 0x20, 0x21, 0x56, 0xcd, 0x69,
  0x90, 0x63, 0x2e, 0x6d, 0xfc, 0x41, 0x04, 0xc0, 0x51, 0xdb, 0x1f, 0x12,
  0x2e, 0x3a, 0x9d, 0xae, 0xc6, 0xb6, 0xc6, 0x0c, 0x17, 0x2f, 0x1d, 0xcd,
  0xc1, 0xd4, 0x36, 0x31, 0x81, 0x83, 0x10, 0xf5, 0x41, 0x01, 0x58, 0x40,
  0xd3, 0x66, 0xb6, 0x03, 0x94, 0xb7, 0xde, 0xf1, 0x25, 0xc0, 0xfd, 0xa6,
  0x23, 0x3c, 0xa4, 0x1b, 0xad, 0x88, 0x8e, 0xeb, 0xc5, 0x73, 0x2a, 0xcd,
  0xc9, 0x16, 0x1b, 0x9d, 0xb5, 0xf9, 0xb2, 0xe0, 0x0c, 0x2e, 0x42, 0x8e,
  0xff, 0xed, 0x66, 0xcd, 0x8f, 0x2b, 0xe6, 0x60, 0x2b, 0x85, 0x76, 0xbb,
  0xbc, 0xc5, 0xe4, 0xe7, 0x68, 0x46, 0x69, 0x83, 0x09, 0xe9, 0x3f, 0x8b,
  0x20, 0x69, 0x07, 0x0d
};
size_t clientCertLen = 136;

uint8_t clientPrivateKeyBuffer[] = {
  0x10, 0x17, 0x25, 0xa3, 0xac, 0x51, 0x75, 0xe8, 0xdf, 0x23, 0x7a, 0x56,
  0x19, 0x80, 0x95, 0xf0, 0x87, 0xa0, 0x2a, 0xf2, 0xaf, 0x63, 0x1c, 0x3e,
  0x11, 0x7d, 0xf1, 0xda, 0x3a, 0x6b, 0x4c, 0x1f, 0x21, 0x56, 0xcd, 0x69,
  0x90, 0x63, 0x2e, 0x6d, 0xfc, 0x41, 0x04, 0xc0, 0x51, 0xdb, 0x1f, 0x12,
  0x2e, 0x3a, 0x9d, 0xae, 0xc6, 0xb6, 0xc6, 0x0c, 0x17, 0x2f, 0x1d, 0xcd,
  0xc1, 0xd4, 0x36, 0x31
};
size_t clientPrivateKeyLen = 64;

void app_main(void)
{
    smolNoice_t* testConn = smolNoice();
    char hostIP[32];
    char* hostURL = HOST_URL;
    uint16_t hostPort = 48032;
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

    //Setup smol-noice
    smolNoiceSetHost(testConn,hostIP,hostPort);
    smolNoiceSetClientCert(testConn,clientCertBuffer,clientCertLen);
    smolNoiceSetClientPrivateKey(testConn,clientPrivateKeyBuffer);

    smolNoiceSetTransportCallback(testConn,clientCb);
    smolNoiceSetRemoteCertCallback(testConn,remoteCertCb);

     //Start application
    smolNoiceStart(testConn);
    while(smolNoiceReadyForTransport(testConn) != SC_OK){
        vTaskDelay(100/portTICK_PERIOD_MS);
    }

    
    while(1){
        vTaskDelay(1000/portTICK_PERIOD_MS);
        pdx++;
        //printf("Waiting... %d\r",pdx);
        //smolNoiceSendData(testConn,1,&pdx);
    }
}

