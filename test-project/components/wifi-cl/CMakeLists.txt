idf_component_register(SRCS "wifi-cl.c" "cmd-wifi-cl.c"
                    INCLUDE_DIRS "include"
                    REQUIRES nvs-cl nvs_flash console)
