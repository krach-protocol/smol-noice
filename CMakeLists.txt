idf_component_register(SRCS "src/handshake.c" "src/sc_packet.c" "src/port/freeRTOS/port_freeRTOS.c"
                       INCLUDE_DIRS "inc" "src/port"
                       REQUIRES noise-c libsodium smolcert-esp32)