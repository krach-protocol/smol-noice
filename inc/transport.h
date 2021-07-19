#ifndef _SC_TRANSPORT_H_
#define _SC_TRANSPORT_H_

#include <internal.h>
#include "smol-noice.h"

#include "sc_err.h"
#include "sn_msg.h"

void printHex(uint8_t*,uint8_t);

sc_err_t encryptAndSendTransport(smolNoice_t*,sn_buffer_t* paket);
sc_err_t decryptTransport(smolNoice_t*,sn_buffer_t* paket);

#endif