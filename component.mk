COMPONENT_SRCDIRS := 	src \
						src/port \
						src/port/* \
						libs/tinycbor/src\
						libs/smolcert-esp32/src 
COMPONENT_ADD_INCLUDEDIRS := 	inc \
								libs/smolcert-esp32/include 
COMPONENT_PRIV_INCLUDEDIRS := 	libs/tinycbor/src \
								libs/smolcert-esp32/include 
COMPONENT_DEPENDS := libdsodium
