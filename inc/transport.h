#ifndef _SC_TRANSPORT_H_
#define _SC_TRANSPORT_H_

#include <internal.h>
#include "smol-noice.h"

#include "sn_err.h"
#include "sn_msg.h"

void printHex(uint8_t*,uint8_t);

sc_err_t encryptAndSendTransport(smolNoice_t*,sn_buffer_t* paket);
sc_err_t decryptTransport(smolNoice_t*,sn_buffer_t* paket);

sn_err_t sn_send_buffer(size_t socket, sn_buffer_t* buf);
sn_err_t sn_read_from_socket(size_t socket, sn_buffer_t* buf, size_t expected_length);

#endif