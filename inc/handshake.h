#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
#include <internal.h>
#include <smolcert.h>
#include "sc_err.h"
#include "sn_msg.h"

typedef sc_err_t (*remoteCertCb_t)(smolcert_t* remoteCert);
typedef sc_err_t (*newTransportCb_t)(uint8_t*,uint8_t);

sc_err_t sc_init(   sn_buffer_t *clientCert,
                    sn_buffer_t *rootCert,
                    remoteCertCb_t certCallback,
                    newTransportCb_t transportCallback,
                    const char *addr,
                    uint16_t port);

sc_err_t sc_destroy(NoiseHandshakeState *handshakeState);

#endif