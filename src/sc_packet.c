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

uint16_t readUint16(uint8_t* buf) {
    uint16_t result = 0;
    result += buf[0] | (buf[1] << 8);
    return result;
}

void sn_write_uint16(uint8_t* buf, uint16_t val) {
    buf[0] = (val & 0x00FF);
    buf[1] = (val & 0xFF00) >> 8;
}

// Reads a single length value block from buf. Buf must start with a LV-block
sc_err_t readLVBlock(uint8_t* buf, uint16_t bufLen, uint8_t** dst, uint16_t *dstlen) {
    if(bufLen < 2) {
        return SC_ERR;
    }
    *dstlen = readUint16(buf);

    if(bufLen < (*dstlen+2)) return SC_ERR; // Provided buffer is too small to contain a valid LV block

    *dst = buf+2;

    return SC_OK;
}

sc_err_t writeLVBlock(uint8_t *buf, uint16_t bufLen, uint8_t *data, uint16_t dataLen, uint16_t *outLen) {
    if(bufLen < dataLen + 2) {
        return SC_ERR;
    }
    uint8_t* writePtr = buf;
    writeUint16(writePtr, dataLen);
    writePtr += 2; // Increase pointer by length of uint16
    memcpy(writePtr, data, dataLen);
    return SC_OK;
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


sc_err_t packHandshakeFin(sn_handshake_fin_packet* packet , sn_msg_t *msg){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;
    uint8_t* writePtr;

    if(packet->HandshakeType != HANDSHAKE_FIN) return SC_PAKET_ERR;
    packetLen = SC_TYPE_LEN + SC_PACKET_LEN_LEN+ SC_ID_LENGTH_LEN + packet->encryptedIdentityLen;// + packet->encryptedPayloadLen ;
    msg->msgLen = (size_t)packetLen;
    msg->msgBuf = (uint8_t*)calloc(1,msg->msgLen);
    writePtr = msg->msgBuf;

    
    memcpy(writePtr,&(packet->HandshakeType),SC_TYPE_LEN);
    writePtr += SC_TYPE_LEN;

    *writePtr = ((packetLen-(SC_TYPE_LEN + SC_PACKET_LEN_LEN))&0x00FF);
    writePtr++;
    *writePtr = ((packetLen-(SC_TYPE_LEN + SC_PACKET_LEN_LEN))&0xFF00)>>8;
    writePtr++;
    

    *writePtr = (packet->encryptedIdentityLen&0x00FF);
    writePtr++;
    *writePtr = (packet->encryptedIdentityLen&0xFF00)>>8;
    writePtr++;
   

    memcpy(writePtr,packet->encryptedIdentity,packet->encryptedIdentityLen);
    writePtr+=packet->encryptedIdentityLen;
    free(packet->encryptedIdentity);

    

    return SC_OK;

}




