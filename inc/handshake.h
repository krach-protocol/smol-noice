#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
#include <internal.h>

typedef enum errorType {SC_OK=0,SC_ERR} sc_err_t;

sc_err_t sc_init(NoiseHandshakeState handshakeState);
sc_err_t sc_destory(NoiseHandshakeState handshakeState);

#endif