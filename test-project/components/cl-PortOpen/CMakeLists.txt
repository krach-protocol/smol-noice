#set(COMPONENT_SRCDIRS ".")
#set(COMPONENT_ADD_INCLUDEDIRS "include")
#register_component(
#REQUIRES cl-MCP23008-HAL cl-gpio-hal console
#)
idf_component_register(SRCS  "cl-PortOpen.c" "cl-PortOpen-cmd.c"
                    INCLUDE_DIRS "include"
                    REQUIRES cl-MCP23008-HAL cl-gpio-hal console )


