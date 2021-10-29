#include "nvs-cl.h"

#include <stdio.h>
#include "argtable3/argtable3.h"
#include "esp_console.h"
#include "esp_log.h"



#define TAG "NVS-CMD"

static struct{
    struct arg_end *end;
} getPrivateKey_args;

static int dogetPrivateKey(int argc, char **argv)
{
    esp_err_t err;
    uint8_t* privateKey = NULL;
    uint8_t keyLen = 0;

    int nerrors = arg_parse(argc, argv, (void **)&getPrivateKey_args);

    if (nerrors != 0)    {
        arg_print_errors(stderr, getPrivateKey_args.end, argv[0]);
        return 0;
    }

    sn_getPrivateKey(&privateKey,&keyLen);
    ESP_LOG_BUFFER_HEXDUMP(TAG,privateKey,keyLen,ESP_LOG_INFO);


    return 0;
}
static void register_sn_getPrivateKey(void){
    getPrivateKey_args.end = arg_end(1);
    const esp_console_cmd_t getPrivateKey_cmd = {
        .command = "getPrivateKey",
        .help = "prints the stored client private key",
        .hint = NULL,
        .func = &dogetPrivateKey,
        .argtable = &getPrivateKey_args};
    ESP_ERROR_CHECK(esp_console_cmd_register(&getPrivateKey_cmd));
}

static struct{
    struct arg_end *end;
} getClientCert_args;

static int dogetClientCert(int argc, char **argv)
{
    esp_err_t err;
    uint8_t* clientCert = NULL;
    uint8_t certLen = 0;

    int nerrors = arg_parse(argc, argv, (void **)&getClientCert_args);

    if (nerrors != 0)    {
        arg_print_errors(stderr, getClientCert_args.end, argv[0]);
        return 0;
    }

    sn_getClientCert(&clientCert,&certLen);
    ESP_LOG_BUFFER_HEXDUMP(TAG,clientCert,certLen,ESP_LOG_INFO);


    return 0;
}
static void register_sn_getClientCert(void){
    getClientCert_args.end = arg_end(1);
    const esp_console_cmd_t getClientCert_cmd = {
        .command = "getClientCert",
        .help = "prints the stored client certificate",
        .hint = NULL,
        .func = &dogetClientCert,
        .argtable = &getClientCert_args};
    ESP_ERROR_CHECK(esp_console_cmd_register(&getClientCert_cmd));
}


static struct{
    struct arg_end *end;
} getRootCert_args;

static int doGetRootCert(int argc, char **argv)
{
    esp_err_t err;
    uint8_t* rootCert;
    uint8_t certLen = 0;

    int nerrors = arg_parse(argc, argv, (void **)&getRootCert_args);

    if (nerrors != 0)    {
        arg_print_errors(stderr, getRootCert_args.end, argv[0]);
        return 0;
    }

    sn_getRootCert(&rootCert,&certLen);
    ESP_LOG_BUFFER_HEXDUMP(TAG,rootCert,certLen,ESP_LOG_INFO);


    return 0;
}
static void register_sn_getRootCert(void){
    getRootCert_args.end = arg_end(1);
    const esp_console_cmd_t getRootCert_cmd = {
        .command = "getRootCert",
        .help = "prints the stored root certificate",
        .hint = NULL,
        .func = &doGetRootCert,
        .argtable = &getRootCert_args};
    ESP_ERROR_CHECK(esp_console_cmd_register(&getRootCert_cmd));
}


void register_NVScl(){
 register_sn_getRootCert();
 register_sn_getClientCert();
 register_sn_getPrivateKey();
}