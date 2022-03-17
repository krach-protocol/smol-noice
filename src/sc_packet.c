#include "sc_packet.h"
#include "sn_err.h"
#include "sn_msg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/** Definitions from here:
 * for humans:      https://github.com/connctd/krach/blob/v2/refactor/spec/index.md
 * for non-humans:  https://github.com/connctd/krach/blob/v2/refactor/spec/protocol.specs
 *
 * */

void printHex(uint8_t*,uint8_t);
void printHex(uint8_t* key,uint8_t keyLen){
  for(uint8_t i = 0; i < keyLen; i++)
  {
    if(i%16 == 0) printf("\n");
    printf("%02x ",key[i]);
    
  }
  printf("\n");
  return;
}

/** Little sidenote:
 * See unpacking and packing discussion here:
 * https://stackoverflow.com/questions/19165134/correct-portable-way-to-interpret-buffer-as-a-struct
 * 
 * Direct casting is okay "as long as alignment, padding, and byte-order" is taken care of.
 * Going safe here by copying - not very memory and runtime efficient but safest way, also fits best the krach specs
 * 
 * Seemingly constant sizes like PACKET,VERSION and TYPE are also memcopied instead of offsetted by array index for
 * future changes like expanding field sizes and for better readability
 * */

sc_err_t pack_handshake_init(sn_handshake_init_packet* packet, sn_buffer_t* buf){
    sn_buffer_reset(buf);
    size_t packetLen;
    uint8_t version = SN_VERSION;
    packet->HandshakeType = HANDSHAKE_INIT // Always set the handshake type, doesn't hurt

    packetLen  =  SN_EPHEMERAL_PUB_KEY_LEN; // We put version and type at the beginning and only count the bytes following that
    
    msg->msgLen = (size_t)packetLen + SN_PACKET_LEN_LEN + SN_VERSION_LEN + SN_TYPE_LEN;
    sn_buffer_ensure_cap(buf, packetLen);

    sn_buffer_write(buf, &version, SN_VERSION_LEN);
    sn_buffer_write(buf, &(packet->HandshakeType), SN_TYPE_LEN);
    
    sn_buffer_write_uint16(buf, (uint16_t)packetLen);
    sn_buffer_write(buf, packet->ephemeralPubKey, SN_EPHEMERAL_PUB_KEY_LEN);
    sn_buffer_rewind(buf);

    return SC_OK;
}

sc_err_t unpack_handshake_response(sn_handshake_response_packet* packet,  sn_buffer_t* buf){
    uint16_t readBytes = 0;
    uint8_t version = 0;
    uint16_t packet_len = 0;
    uint8_t* readPtr = msg->msgBuf;
    sc_err_t err = SC_OK;
    if(( err = sn_buffer_read(buf, (uint8_t*)&(packet->HandshakeType), SC_TYPE_LEN) != SC_OK) {
        return err;
    }
    if (packet->HandshakeType != HANDSHAKE_RESPONSE) {
        return SC_PAKET_ERR;
    }

    if((err = sn_buffer_read_uint16(buf, &packet_len)) != SC_OK) {
        return err;
    }
    if(packet_len != buf->len) {
        return SC_PAKET_ERR;
    }

    packet->ephemeralPubKey = (uint8_t*)calloc(SN_EPHEMERAL_PUB_KEY_LEN,sizeof(uint8_t));
    if((err = sn_buffer_read(buf, (uint8_t*)(packet->ephemeralPubkey), SN_EPHEMERAL_PUB_KEY_LEN)) != SC_OK ) {
        return err;
    }
    packet->smolcertLen = sn_buffer_peek_lv_len(buf);
    packet->smolcert = (uint8_t*)calloc(1, packet->smolcertLen);

    if((err = sn_buffer_read_lv_block(buf, packet->smolcert, packet->smolcertLen)) != SC_OK) {
        return err;
    }

    packet->payloadLen = sn_buffer_peek_lv_len(buf);
    packet->payload = (uint8_t*)calloc(1, packet->payloadLen);
    if((err = sn_buffer_read_lv_block(buf, packet->payload, packet->payloadLen)) != SC_OK) {
        return err;
    }
    
    return err;
}


sc_err_t pack_handshake_fin(sn_handshake_fin_packet* packet, sn_buffer_t* buf){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;
    uint8_t* writePtr;

    packet->HandshakeType = HANDSHAKE_FIN;
    packetLen = SN_TYPE_LEN + SN_PACKET_LEN_LEN+ SN_ID_LENGTH_LEN + packet->encryptedIdentityLen;// + packet->encryptedPayloadLen ;
    sn_buffer_ensure_cap(buf, (size_t)packetLen);

    sn_buffer_write(buf, &(packet->HandshakeType), SN_TYPE_LEN);    
    sn_buffer_write_uint16(buf, packetLen - SN_TYPE_LEN - SN_PACKET_LEN_LEN);

    sn_buffer_write_lv_block(buf, packet->encryptedIdentity, packet->encryptedIdentityLen);    

    return SC_OK;
}




