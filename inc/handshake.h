#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
#include <internal.h>
#include <smolcert.h>
#include "sc_err.h"

sc_err_t sc_init(smolcert_t *cert,char *addr,uint16_t port);
sc_err_t sc_destroy(NoiseHandshakeState handshakeState);

#endif