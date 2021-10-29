/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "wifi-cl.h"

#include <sodium.h>

/*#include "handshake.h"
#include "sc_packet.h"
#include "sc_err.h"
*/

#include "smol-noice.h"

sc_err_t clientCb(uint8_t* data, uint8_t len);

sc_err_t clientCb(uint8_t* data, uint8_t len){
    for(uint8_t idx = 0; idx < len; idx++){
        printf("%c",data[idx]);
    }
    return SC_OK;
}

sc_err_t remoteCertCb(uint8_t* data, uint8_t len, smolcert_t* remoteCert);

sc_err_t remoteCertCb(uint8_t* data, uint8_t len, smolcert_t* remoteCert){
    for(uint8_t idx = 0; idx < len; idx++){
        printf("%c",data[idx]);
    }
    return SC_OK;
}





void app_main(void)
{
    smolNoice_t* testConn = smolNoice();
    const char* host = "127.0.0.1";
    uint8_t clientCertBuffer[256];
    uint8_t clientCertLen = 255;
    uint8_t clientPrivateKey[32];


    esp_err_t err;
    char hostIP[32];
    char URL[] = HOST_URL;
    if( initNVS() != ESP_OK) printf("Error opening NVS\n");
    if(clPortOpeninitLock() != ESP_OK) printf("Error initialzing Lock HAL\n");
    wifi_init_sta(); 

    
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

     EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);
     if (bits & WIFI_CONNECTED_BIT) {
        
        //Application Code
       
        while( !DNSFound ){
            ip_addr_t ip_Addr;
            IP_ADDR4( &ip_Addr, 0,0,0,0 );  
            dns_gethostbyname(URL, &ip_Addr, dns_found_cb, &hostIP );
            vTaskDelay(200/portTICK_PERIOD_MS);
        }
        

    printf("IP Adress for %s is %s\n",URL,hostIP);
}

    uint8_t pdx = 0;

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
    

    // Currently this won't execute in a meaningful way, this is to test the build process
    /*
    smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
    sn_buffer_t clientCertBuffer;
    sn_buffer_t rootCertBuffer;
    sc_init(&clientCertBuffer,&rootCertBuffer,NULL,NULL,host,9095);
    */

}
