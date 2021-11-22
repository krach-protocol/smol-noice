
#include "driver/i2c.h"
#include "cl-I2C-HAL.h"

#define I2C_PORT I2C_NUM_0
#define I2C_SCL GPIO_NUM_19
#define I2C_SDA GPIO_NUM_18
#define I2C_FREQ 400000

esp_err_t I2Cinit();
esp_err_t I2Cinit_done();

init_ptr clI2Cinit = &I2Cinit;

esp_err_t I2Cinit(){
    esp_err_t err;
    i2c_config_t conf = { .mode = I2C_MODE_MASTER,
			      .sda_io_num = I2C_SDA,
			      .sda_pullup_en = GPIO_PULLUP_DISABLE,
			      .scl_io_num = I2C_SCL,
			      .scl_pullup_en = GPIO_PULLUP_DISABLE,
			      .master.clk_speed = I2C_FREQ };
	err = i2c_param_config(I2C_PORT, &conf);
    
    if(err != ESP_OK){
        return err;
    }

    err = i2c_driver_install(I2C_PORT, I2C_MODE_MASTER, 0, 0, 0);
    if(err != ESP_OK){
        return err;
    }
    clI2Cinit = I2Cinit_done;
    return err;
}

esp_err_t I2Cinit_done(){
    return ESP_OK;
}
esp_err_t clI2Cdeinit(){
    esp_err_t err;
    err = i2c_driver_delete(I2C_PORT);
    if(err != ESP_OK){
        return err;
    }
    clI2Cinit = I2Cinit;
    return err;
}

esp_err_t clI2Csend(uint8_t address, uint8_t reg, uint8_t data){
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
	i2c_master_start(cmd);
	i2c_master_write_byte(cmd, (address << 1) | I2C_MASTER_WRITE, 0x1);
	i2c_master_write_byte(cmd, reg, 0x01);
	i2c_master_write_byte(cmd, data, 0x01);
	i2c_master_stop(cmd);

	esp_err_t ret = i2c_master_cmd_begin(I2C_PORT, cmd, 50 / portTICK_RATE_MS);
	i2c_cmd_link_delete(cmd);
	
    if( ret != ESP_OK ) {
        return ESP_FAIL;
    }
    return ESP_OK;  
}

esp_err_t clI2Cread(uint8_t address, uint8_t reg, uint8_t *data){

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (address << 1) | I2C_MASTER_WRITE, 0x01);
    i2c_master_write_byte(cmd, reg, 0x01);
    i2c_master_stop(cmd);

    esp_err_t ret = i2c_master_cmd_begin(I2C_PORT, cmd, 1000/portTICK_RATE_MS);
    i2c_cmd_link_delete(cmd);
    if( ret != ESP_OK ) {
        return ESP_FAIL;
    }
    vTaskDelay(30/portTICK_RATE_MS);

    cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (address << 1) | I2C_MASTER_READ, 0x01);
    i2c_master_read_byte(cmd, data, 0x00);
    i2c_master_stop(cmd);

    ret = i2c_master_cmd_begin(I2C_PORT, cmd, 1000/portTICK_RATE_MS);
    i2c_cmd_link_delete(cmd);
    if( ret != ESP_OK ) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

