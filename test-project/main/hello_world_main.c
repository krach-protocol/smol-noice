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
#include "handshake.h"
#include "sc_packet.h"
#include "sc_err.h"

void app_main(void)
{
    // Currently this won't execute in a meaningful way, this is to test the build process
    smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
    sn_buffer_t clientCertBuffer;
    sn_buffer_t rootCertBuffer;
    const char* host = "127.0.0.1";
    sc_init(&clientCertBuffer,&rootCertBuffer,NULL,NULL,host,9095);
}
