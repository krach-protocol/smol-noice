#set(COMPONENT_SRCDIRS ".")
#set(COMPONENT_ADD_INCLUDEDIRS "include")
#register_component()

idf_component_register(SRCS  "cmd-nvs-cl.c" "nvs-cl.c"
                    INCLUDE_DIRS "include"
                    REQUIRES nvs_flash console )
