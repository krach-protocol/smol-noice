#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
#include <internal.h>
#include <smolcert.h>

#include "sc_err.h"
#include "sn_msg.h"
#include "sc_packet.h"
#include "smol-noice.h"

sc_err_t sc_init(smolNoice_t* smolNoice);
sc_err_t sc_destroy(smolNoice_t* smolNoice);

sc_err_t writeMessageE(smolNoice_t* smolNoice,sc_handshakeInitPacket* packet);

sc_err_t writeMessageS_DHSE(smolNoice_t* smolNoice, sc_handshakeFinPacket* packet);
sc_err_t writeMessageS(smolNoice_t* smolNoice,sc_handshakeFinPacket* packet);
sc_err_t writeMessageDHSE(smolNoice_t* smolNoice, sc_handshakeFinPacket* packet);

sc_err_t readMessageE_DHEE_S_DHES(smolNoice_t* smolNoice,sc_handshakeResponsePacket *packet);
sc_err_t readMessageE(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet);
sc_err_t readMessageDHEE(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet);
sc_err_t readMessageS(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet);
sc_err_t readMessageDHES(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet);

sc_err_t splitCipher(smolNoice_t* smolNoice);


#endif