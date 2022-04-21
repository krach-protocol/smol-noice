#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
#include <internal.h>
#include <smolcert.h>

#include "sn_err.h"
#include "sn_buffer.h"
#include "sn_packet.h"
#include "smol-noice.h"

sc_err_t sn_init(smolNoice_t* smolNoice);
sc_err_t run_handshake(smolNoice_t* smol_noice);

sc_err_t writeMessageE(smolNoice_t* smolNoice,sn_handshake_init_packet* packet);

sc_err_t writeMessageS_DHSE(smolNoice_t* smolNoice, sn_handshake_fin_packet* packet);
sc_err_t writeMessageS(smolNoice_t* smolNoice,sn_handshake_fin_packet* packet);
sc_err_t writeMessageDHSE(smolNoice_t* smolNoice, sn_handshake_fin_packet* packet);

sc_err_t readMessageE_DHEE_S_DHES(smolNoice_t* smolNoice,sn_handshake_response_packet *packet);
sc_err_t readMessageE(smolNoice_t* smolNoice, sn_handshake_response_packet *packet);
sc_err_t readMessageDHEE(smolNoice_t* smolNoice, sn_handshake_response_packet *packet);
sc_err_t readMessageS(smolNoice_t* smolNoice, sn_handshake_response_packet *packet);
sc_err_t readMessageDHES(smolNoice_t* smolNoice, sn_handshake_response_packet *packet);

sc_err_t sn_split_cipher(smolNoice_t* smolNoice);


#endif