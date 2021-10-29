idf_component_register(SRCS "hello_world_main.c"
                    INCLUDE_DIRS ""
                    REQUIRES smol-noice smolcert-esp32 esp_system spi_flash libsodium nvs-cl cl-PortOpen wifi-cl cl-MCP23008-HAL console)