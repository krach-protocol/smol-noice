#include "wifi-cl.h"

#include "argtable3/argtable3.h"
#include "esp_console.h"

static struct {
    struct arg_str *ssid;
    struct arg_str *password;
    struct arg_end *end;
} setWifi_args;
static int connect(int argc, char **argv)
{
    esp_err_t err;
    int nerrors = arg_parse(argc, argv, (void **) &setWifi_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, setWifi_args.end, argv[0]);
        return 1;
    }
    
    err = clWifiSetCredentials(setWifi_args.ssid->sval[0],setWifi_args.password->sval[0]);
    if(err != ESP_OK){
        return 1;
    } else {
        return 0;
    }
}
void register_SetWifi(void)
{
    setWifi_args.ssid = arg_str1(NULL, NULL, "<ssid>", "SSID of AP");
    setWifi_args.password = arg_str0(NULL, NULL, "<pass>", "PSK of AP");
    setWifi_args.end = arg_end(2);

    const esp_console_cmd_t join_cmd = {
        .command = "setWifiCreds",
        .help = "Set Wifi Credentials",
        .hint = NULL,
        .func = &connect,
        .argtable = &setWifi_args
    };

    ESP_ERROR_CHECK( esp_console_cmd_register(&join_cmd) );
}


static struct {
    struct arg_end *end;
} get_args;

static int getCreds(int argc, char **argv){
    clWifiGetCredentials();

    return 0;
}

void register_GetWifi(void)
{
    get_args.end = arg_end(1);

    const esp_console_cmd_t get_cmd = {
        .command = "getWifiCreds",
        .help = "Get Wifi Credentials",
        .hint = NULL,
        .func = &getCreds,
        .argtable = &get_args
    };

    ESP_ERROR_CHECK( esp_console_cmd_register(&get_cmd) );
}

void register_wifiCL(void){
    register_GetWifi();
    register_SetWifi();
}