#ifndef _SC_TRANSPORT_H_
#define _SC_TRANSPORT_H_

#include <internal.h>
#include "smol-noice.h"

#include "sn_err.h"
#include "sn_buffer.h"

void printHex(uint8_t*,uint8_t);

uint8_t open_socket(smolNoice_t* smolNoice);
void close_socket(smolNoice_t* smol_noice);
sn_err_t sn_send_buffer(int socket, sn_buffer_t* buf);
sn_err_t sn_read_from_socket(int socket, sn_buffer_t* buf, size_t expected_length);

#endif