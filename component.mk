COMPONENT_SRCDIRS := 	src \
						libs/tinycbor/src\
						libs/smolcert-esp32/src \
						libs/noise-c/src \
#						libs/noise-c/src/protocol \
#						libs/noise-c/src/crypto/* \
#						libs/noise-c/src/backend/ref \
#						libs/noise-c/src/crypto/goldilocks/src \
#						libs/noise-c/src/crypto/goldilocks/src/* \
COMPONENT_ADD_INCLUDEDIRS := 	inc \
								libs/smolcert-esp32/include \
								libs/noise-c/include/ 
COMPONENT_PRIV_INCLUDEDIRS := 	libs/tinycbor/src \
								libs/smolcert-esp32/include \
								libs/noise-c/include
#								libs/noise-c/include/keys \
#								libs/noise-c/include/protocol \
#								libs/noise-c/src/protocol \
#								libs/noise-c/include/protocol \
#								libs/noise-c/src/ \
#								libs/noise-c/src/crypto/goldilocks/src/include \
#								libs/noise-c/src/crypto/goldilocks/src/p448/ \
#								libs/noise-c/src/crypto/goldilocks/src/p448/arch_32 
COMPONENT_DEPENDS := libdosium
