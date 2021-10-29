#set(COMPONENT_SRCDIRS ".")
#set(COMPONENT_ADD_INCLUDEDIRS "include")
#register_component()

idf_component_register(SRCS  "cl-gpio-hal.c"
                    INCLUDE_DIRS "include")
