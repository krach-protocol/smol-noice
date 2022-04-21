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

#include <sodium.h>

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

    uint8_t pdx = 0;

    sn_set_host(testConn,host,9095);
    sn_set_client_cert(testConn,clientCertBuffer,clientCertLen);
    sn_set_client_priv_key(testConn,clientPrivateKey);

    sn_set_remote_cert_callback(testConn,remoteCertCb);
    sn_connect(testConn);

    while(1){
        vTaskDelay(1000/portTICK_PERIOD_MS);
        pdx++;
        printf("Sending %d \n",pdx);
        sn_send(testConn, (uint8_t*)&pdx, 1);
    }
    

    // Currently this won't execute in a meaningful way, this is to test the build process
    /*
    smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
    sn_buffer_t clientCertBuffer;
    sn_buffer_t rootCertBuffer;
    sn_init(&clientCertBuffer,&rootCertBuffer,NULL,NULL,host,9095);
    */

}
