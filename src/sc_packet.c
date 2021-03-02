#include "sc_packet.h"
#include "sc_err.h"
#include <stdlib.h>
#include <string.h>

/** Definitions from here:
 * for humans:      https://github.com/connctd/krach/blob/v2/refactor/spec/index.md
 * for non-humans:  https://github.com/connctd/krach/blob/v2/refactor/spec/protocol.specs
 *
 * */

// length in bytes
#define SC_PACKET_LEN_LEN          2
#define SC_VERSION_LEN             1
#define SC_TYPE_LEN                1
#define SC_EPHEMERAL_PUB_KEY_LEN   32
#define SC_MAX_PACKET_LEN          512 //set at runtime

#define SC_VERSION                 0x01


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

sc_err_t packHandshakeInit(sc_handshakeInitPacket* packet, sn_msg_t *msg){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;

    if(packet->HandshakeType != HANDSHAKE_INIT) return SC_PAKET_ERR;

    packetLen  = SC_VERSION_LEN + SC_TYPE_LEN + SC_EPHEMERAL_PUB_KEY_LEN;
    
    msg->msgLen = (size_t)packetLen + SC_PACKET_LEN_LEN;
    msg->msgBuf = (uint8_t*)malloc(msg->msgLen);
    uint8_t* writePtr = msg->msgBuf;

    //Write packet length to buffer and pay due to endianess
    *writePtr = (packetLen&0xFF00)>>8;
    writePtr++;
    *writePtr = (packetLen&0xFF);
    writePtr++;

    memcpy(writePtr,&version, SC_VERSION_LEN);
    writePtr += SC_VERSION_LEN;


    memcpy(writePtr,&(packet->HandshakeType),SC_TYPE_LEN);
    writePtr += SC_TYPE_LEN;

    memcpy(writePtr,packet->ephemeralPubKey,SC_EPHEMERAL_PUB_KEY_LEN);
    
    return SC_OK;
}

sc_err_t unpackHandshakeResponse(sc_handshakeResponsePacket* packet,  sn_msg_t *msg){
    uint16_t readBytes = 0;
    uint8_t version = 0;
    uint16_t packetLen = 0;

    memcpy(&(packetLen), msg->msgBuf,SC_PACKET_LEN_LEN);
    if((readBytes + SC_PACKET_LEN_LEN) > SC_MAX_PACKET_LEN) return SC_PAKET_ERR;
    msg->msgBuf += SC_PACKET_LEN_LEN;
    
    memcpy(&version,msg->msgBuf,SC_VERSION_LEN);
    if((readBytes += SC_VERSION_LEN) > packetLen) return SC_PAKET_ERR;
    msg->msgBuf += SC_VERSION_LEN;
    if(version > SC_VERSION) return SC_PAKET_ERR;

    memcpy((uint8_t*)&(packet->HandshakeType),msg->msgBuf,SC_TYPE_LEN);
    if((readBytes += SC_TYPE_LEN) > packetLen) return SC_PAKET_ERR;
    msg->msgBuf += SC_TYPE_LEN;
    if(packet->HandshakeType != HANDSHAKE_RESPONSE) return SC_PAKET_ERR;

    packet->ephemeralPubKey = (uint8_t*)malloc(SC_EPHEMERAL_PUB_KEY_LEN);
    memcpy((uint8_t*)(packet->ephemeralPubKey),msg->msgBuf,SC_EPHEMERAL_PUB_KEY_LEN);
    if((readBytes += SC_EPHEMERAL_PUB_KEY_LEN) > packetLen) return SC_PAKET_ERR;
    msg->msgBuf += SC_EPHEMERAL_PUB_KEY_LEN;

    packet->encryptedPayloadLen = packetLen - readBytes;
    packet->encryptedPayload = (uint8_t*)malloc(packet->encryptedPayloadLen);
    memcpy((uint8_t*)(packet->encryptedPayload),msg->msgBuf,packet->encryptedPayloadLen);
    
    return SC_OK;
}


sc_err_t packHandshakeFin(sc_handshakeFinPacket* packet , sn_msg_t *msg){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;

    if(packet->HandshakeType != HANDSHAKE_FIN) return SC_PAKET_ERR;
    
    packetLen = SC_PACKET_LEN_LEN + SC_VERSION_LEN + SC_TYPE_LEN + packet->encryptedPayloadLen;
    
    msg->msgLen = (size_t)packetLen;
    msg->msgBuf = (uint8_t*)malloc(msg->msgLen);

    memcpy(msg->msgBuf,&packetLen, SC_PACKET_LEN_LEN);
    msg->msgBuf += SC_PACKET_LEN_LEN;

    memcpy(msg->msgBuf,&version, SC_VERSION_LEN);
    msg->msgBuf += SC_VERSION_LEN;

    memcpy(msg->msgBuf,&(packet->HandshakeType),SC_TYPE_LEN);
    msg->msgBuf += SC_TYPE_LEN;

    memcpy(msg->msgBuf,&(packet->encryptedPayload),packet->encryptedPayloadLen);
    
    return SC_OK;

}

sc_err_t unpackTransport(sc_transportPacket* packet,  sn_msg_t *msg){
    uint16_t packetLen;
    return SC_OK;
}
sc_err_t packTransport(sc_transportPacket* packet, sn_msg_t *msg){
    uint16_t packetLen;
    return SC_OK;
}
