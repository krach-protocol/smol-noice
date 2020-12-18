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


sc_err_t packHandshakeInit(sc_handshakeInitPacket* packet, uint8_t** msgBuffer, size_t* msgLen){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;

    if(packet->HandshakeType != HANDSHAKE_INIT) return SC_PAKET_ERR;

    packetLen  = SC_PACKET_LEN_LEN + SC_VERSION_LEN + SC_TYPE_LEN + SC_EPHEMERAL_PUB_KEY_LEN;

    *msgLen = (size_t)packetLen;
    *msgBuffer = (uint8_t*)malloc(*msgLen);


    memcpy(*msgBuffer,&packetLen, SC_PACKET_LEN_LEN);
    *msgBuffer += SC_PACKET_LEN_LEN;

    memcpy(*msgBuffer,&version, SC_VERSION_LEN);
    *msgBuffer += SC_VERSION_LEN;


    memcpy(*msgBuffer,&(packet->HandshakeType),SC_TYPE_LEN);
    *msgBuffer += SC_TYPE_LEN;

    memcpy(*msgBuffer,&(packet->ephemeralPubKey),SC_EPHEMERAL_PUB_KEY_LEN);

    return SC_OK;
}

sc_err_t unpackHandshakeResponse(sc_handshakeResponsePacket* packet, uint8_t* msgBuffer, uint8_t msgLen){
    uint16_t readBytes = 0;
    uint8_t version;
    packet = (sc_handshakeResponsePacket*)malloc(sizeof(sc_handshakeResponsePacket));

    memcpy(&(packet->packetLen), msgBuffer,SC_PACKET_LEN_LEN);
    if((readBytes += SC_PACKET_LEN_LEN) > SC_MAX_PACKET_LEN) return SC_PAKET_ERR;
    msgBuffer += SC_PACKET_LEN_LEN;

    memcpy(&version,msgBuffer,SC_VERSION_LEN);
    if((readBytes += SC_VERSION_LEN) > packet->packetLen) return SC_PAKET_ERR;
    msgBuffer += SC_VERSION_LEN;
    if(version > SC_VERSION) return SC_PAKET_ERR;

    memcpy(&(packet->HandshakeType),msgBuffer,SC_TYPE_LEN);
    if((readBytes += SC_TYPE_LEN) > packet->packetLen) return SC_PAKET_ERR;
    msgBuffer += SC_TYPE_LEN;
    if(packet->HandshakeType != HANDSHAKE_FIN) return SC_PAKET_ERR;

    memcpy(&(packet->ephemeralPubKey),msgBuffer,SC_EPHEMERAL_PUB_KEY_LEN);
    if((readBytes += SC_EPHEMERAL_PUB_KEY_LEN) > packet->packetLen) return SC_PAKET_ERR;
    msgBuffer += SC_EPHEMERAL_PUB_KEY_LEN;

    packet->encryptedPayloadLen = packet->packetLen - readBytes;
    memcpy(&(packet->encryptedPayload),msgBuffer,packet->encryptedPayloadLen);
    
    return SC_OK;
}


sc_err_t packHandshakeFin(sc_handshakeFinPacket* packet ,uint8_t** msgBuffer, size_t* msgLen){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;

    if(packet->HandshakeType != HANDSHAKE_FIN) return SC_PAKET_ERR;
    
    packetLen = SC_PACKET_LEN_LEN + SC_VERSION_LEN + SC_TYPE_LEN + packet->encryptedPayloadLen;
    
    *msgLen = (size_t)packetLen;
    *msgBuffer = (uint8_t*)malloc(*msgLen);

    memcpy(*msgBuffer,&packetLen, SC_PACKET_LEN_LEN);
    *msgBuffer += SC_PACKET_LEN_LEN;

    memcpy(*msgBuffer,&version, SC_VERSION_LEN);
    *msgBuffer += SC_VERSION_LEN;

    memcpy(*msgBuffer,&(packet->HandshakeType),SC_TYPE_LEN);
    *msgBuffer += SC_TYPE_LEN;

    memcpy(*msgBuffer,&(packet->encryptedPayload),packet->encryptedPayloadLen);
    
    return SC_OK;

}

sc_err_t unpackTransport(sc_transportPacket* packet, uint8_t* msgBuffer, size_t msgLen){
    uint16_t packetLen;
    return SC_OK;
}
sc_err_t packTransport(sc_transportPacket* packet, uint8_t* msgBuffer, size_t* msgLen){
    uint16_t packetLen;
    return SC_OK;
}
