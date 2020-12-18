#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
#include <internal.h>
#include "sc_err.h"

sc_err_t sc_init(void);
sc_err_t sc_destroy(NoiseHandshakeState handshakeState);

#endif