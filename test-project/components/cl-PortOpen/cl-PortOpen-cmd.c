#include "cl-PortOpen.h"

#include <stdio.h>
#include "argtable3/argtable3.h"
#include "esp_console.h"
#include "esp_log.h"




static struct{
    struct arg_end *end;
} closeAll_args;

static int doCloseAll(int argc, char **argv)
{
    char *OtaUrl=NULL, *OtaHash=NULL, *Serial=NULL, *PrivateKey=NULL,*ConnString=NULL;
    //char OtaUrl[64], OtaHash[64], Serial[64], PrivateKey[64];
    esp_err_t err;

    int nerrors = arg_parse(argc, argv, (void **)&closeAll_args);

    if (nerrors != 0)    {
        arg_print_errors(stderr, closeAll_args.end, argv[0]);
        return 0;
    }
    for(uint8_t i = 0; i<=20; i++){
        clPortOpenOpen(i);
    }


    return 0;
}
static void register_closeAll(void){
    closeAll_args.end = arg_end(1);
    const esp_console_cmd_t closeAll_cmd = {
        .command = "closeAll",
        .help = "",
        .hint = NULL,
        .func = &doCloseAll,
        .argtable = &closeAll_args};
    ESP_ERROR_CHECK(esp_console_cmd_register(&closeAll_cmd));
}





static struct{
    struct arg_end *end;
} openAll_args;

static int doOpenAll(int argc, char **argv)
{
    char *OtaUrl=NULL, *OtaHash=NULL, *Serial=NULL, *PrivateKey=NULL,*ConnString=NULL;
    //char OtaUrl[64], OtaHash[64], Serial[64], PrivateKey[64];
    esp_err_t err;

    int nerrors = arg_parse(argc, argv, (void **)&openAll_args);

    if (nerrors != 0)    {
        arg_print_errors(stderr, openAll_args.end, argv[0]);
        return 0;
    }
    for(uint8_t i = 0; i<=20; i++){
        clPortOpenOpen(i);
    }


    return 0;
}
static void register_openAll(void){
    openAll_args.end = arg_end(1);
    const esp_console_cmd_t openAll_cmd = {
        .command = "openAll",
        .help = "",
        .hint = NULL,
        .func = &doOpenAll,
        .argtable = &openAll_args};
    ESP_ERROR_CHECK(esp_console_cmd_register(&openAll_cmd));
}


void register_PortOpen(){
    register_closeAll();
    register_openAll();
}