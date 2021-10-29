#include "cl-gpio-hal.h"

#define AUX_PRESENT GPIO_NUM_39

esp_err_t clGpioInitBulkCheck(){
    esp_err_t err;
    gpio_config_t gpioInputConf;

    gpioInputConf.intr_type = GPIO_PIN_INTR_DISABLE;
    gpioInputConf.mode = GPIO_MODE_INPUT;
    gpioInputConf.pin_bit_mask = (1ULL<<AUX_PRESENT);
    gpioInputConf.pull_down_en = 0;
    gpioInputConf.pull_up_en = 0;
    err = gpio_config(&gpioInputConf);

    return err;
}

esp_err_t clGpioInitLockPins(){
    esp_err_t err;

    gpio_config_t gpioOutputConf;

    gpioOutputConf.intr_type = GPIO_PIN_INTR_DISABLE;
    gpioOutputConf.mode = GPIO_MODE_OUTPUT;
    gpioOutputConf.pin_bit_mask = (1ULL<<LOCK_1) | (1ULL<<LOCK_2) | (1ULL<<LOCK_19) | (1ULL<<LOCK_20);
    gpioOutputConf.pull_down_en = 0;
    gpioOutputConf.pull_up_en = 0;
    
    err = gpio_config(&gpioOutputConf);
    return err;
}

esp_err_t clGpioSetPinState(uint8_t pin,uint8_t state){
    return gpio_set_level(pin, state);
}

uint32_t clGpioGetAuxState(){
    int ret;
    ret = gpio_get_level(AUX_PRESENT);
    return ret;
}

