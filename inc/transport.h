#ifndef _SC_TRANSPORT_H_
#define _SC_TRANSPORT_H_

#include <internal.h>

#include "sc_err.h"
#include "sn_msg.h"

sc_err_t encryptTransport(NoiseCipherState* txCipher,sn_buffer_t* paket);
sc_err_t decryptTransport(NoiseCipherState* rxCipher,sn_buffer_t* paket);

#endif