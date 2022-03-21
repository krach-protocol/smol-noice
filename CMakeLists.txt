idf_component_register(SRCS "src/smol-noice.c" "src/handshake.c" "src/sn_buffer.c" "src/sc_err.c" "src/transport.c" "src/sc_packet.c"
                       INCLUDE_DIRS "inc"
                       REQUIRES noise-c libsodium smolcert-esp32)
