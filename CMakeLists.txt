idf_component_register(SRCS "src/smol-noice.c" "src/statemachine.c" "src/handshake.c" "src/sn_buffer.c" "src/sc_err.c" "src/transport.c" "src/sc_packet.c" "src/port/freeRTOS/port_freeRTOS.c" "src/port/freeRTOS/queue.c"
                       INCLUDE_DIRS "inc" "src/port"
                       REQUIRES noise-c libsodium smolcert-esp32)
set_target_properties(${COMPONENT_LIB} PROPERTIES COMPILE_FLAGS "-Wno-unused-variable -Wno-unused-but-set-variable")
