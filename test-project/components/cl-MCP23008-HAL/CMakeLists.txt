#set(COMPONENT_SRCDIRS ".")
#set(COMPONENT_ADD_INCLUDEDIRS "include")
#register_component(
#REQUIRES cl-I2C-HAL
#)

idf_component_register(SRCS "cl-MCP23008-HAL.c"
                    INCLUDE_DIRS "include"
                    REQUIRES cl-I2C-HAL)
