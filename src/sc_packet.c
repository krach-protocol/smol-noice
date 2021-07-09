#include "sc_packet.h"
#include "sc_err.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
/** Definitions from here:
 * for humans:      https://github.com/connctd/krach/blob/v2/refactor/spec/index.md
 * for non-humans:  https://github.com/connctd/krach/blob/v2/refactor/spec/protocol.specs
 *
 * */

// length in bytes
#define SC_PACKET_LEN_LEN          2
#define SC_ID_LENGTH_LEN           2
#define SC_VERSION_LEN             1
#define SC_TYPE_LEN                1
#define SC_EPHEMERAL_PUB_KEY_LEN   32
#define SC_MAX_PACKET_LEN          512 //set at runtime

#define SC_VERSION                 0x01

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

void writeUint16(uint8_t* buf, uint16_t val) {
    buf[0] = (val & 0x00FF);
    buf[1] = (val & 0xFF00) >> 8;
}

// Reads a single length value block from buf. Buf must start with a LV-block
sc_err_t readLVBlock(uint8_t* buf, uint16_t bufLen, uint8_t** dst, uint16_t *dstlen) {
    if(bufLen < 2) {
        return SC_ERR;
    }
    *dstlen = readUint16(buf);
    if(bufLen < (*dstlen+2)) {
        // Provided buffer is too small to contain a valid LV block
        return SC_ERR;
    }
    
    if(*dstlen+2 > bufLen) {
        return SC_ERR;
    }

    /*dst = (uint8_t*)malloc(*dstlen);
    if(dst == NULL) {
        // Allocation failed
        return SC_ERR;
    }
    memcpy(dst, buf+2, *dstlen);*/
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

sc_err_t packHandshakeInit(sc_handshakeInitPacket* packet, sn_msg_t *msg){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;
    uint8_t* writePtr;
    if(packet->HandshakeType != HANDSHAKE_INIT) return SC_PAKET_ERR;

    packetLen  =  SC_EPHEMERAL_PUB_KEY_LEN; // We put version and type at the beginning and only count the bytes following that
    
    msg->msgLen = (size_t)packetLen + SC_PACKET_LEN_LEN + SC_VERSION_LEN + SC_TYPE_LEN;
    msg->msgBuf = (uint8_t*)malloc(msg->msgLen);
    writePtr = msg->msgBuf;

    memcpy(writePtr,&version, SC_VERSION_LEN);
    writePtr++;
    memcpy(writePtr,&(packet->HandshakeType),SC_TYPE_LEN);
    writePtr += SC_TYPE_LEN;
    //Write packet length to buffer and pay due to endianess
    
    *writePtr = (packetLen&0x00FF);
    writePtr++;
    *writePtr = (packetLen&0xFF00)>>8;
    writePtr++;
    

    memcpy(writePtr,packet->ephemeralPubKey,SC_EPHEMERAL_PUB_KEY_LEN);
    printf("Init packet\n");
    printHex(msg->msgBuf,msg->msgLen);


    return SC_OK;
}

sc_err_t unpackHandshakeResponse(sc_handshakeResponsePacket* packet,  sn_msg_t *msg){
    uint16_t readBytes = 0;
    uint8_t version = 0;
    uint16_t packetLen = 0;
    uint8_t* readPtr = msg->msgBuf;
    sc_err_t err = SC_OK; 
    memcpy((uint8_t*)&(packet->HandshakeType), readPtr,SC_TYPE_LEN);
    if (packet->HandshakeType != HANDSHAKE_RESPONSE) {
        return SC_PAKET_ERR;
    }

    printf("Unpacking Response: \n");
    printHex(msg->msgBuf,msg->msgLen);

    readPtr += SC_TYPE_LEN;
    readBytes += SC_TYPE_LEN;
    printf("Parsed Handshake Response @ %d bytes read\n",readBytes);
    if((readBytes + SC_PACKET_LEN_LEN + SC_TYPE_LEN) > SC_MAX_PACKET_LEN) return SC_PAKET_ERR;
    
    packetLen = readUint16(readPtr);
    readPtr += SC_PACKET_LEN_LEN;
    readBytes += SC_PACKET_LEN_LEN;
    printf("Got paket len of %d bytes @ %d bytes read\n",packetLen,readBytes);
    if(readBytes >= (packetLen+SC_TYPE_LEN + SC_PACKET_LEN_LEN)) return SC_PAKET_ERR;
    


    packet->ephemeralPubKey = (uint8_t*)malloc(SC_EPHEMERAL_PUB_KEY_LEN);
    memcpy((uint8_t*)(packet->ephemeralPubKey),readPtr,SC_EPHEMERAL_PUB_KEY_LEN);
    readPtr += SC_EPHEMERAL_PUB_KEY_LEN;
    readBytes += SC_EPHEMERAL_PUB_KEY_LEN;
    printf("Got ephemereal Pubkey@ %d bytes read\n",readBytes);
    printHex(packet->ephemeralPubKey,SC_EPHEMERAL_PUB_KEY_LEN);

    err = readLVBlock(readPtr, packetLen-(readBytes-SC_TYPE_LEN-SC_PACKET_LEN_LEN), &packet->smolcert, &packet->smolcertLen);
    if(err != SC_OK) {
        return err;
    }
    readPtr += (packet->smolcertLen+2);
    readBytes += (packet->smolcertLen+2);

    printf("Got remote smolcert@ %d bytes read\n",readBytes);
    printf("Smolcerlen: %d, unpadded len:%d\n",packet->smolcertLen,packet->smolcertLen-packet->smolcertLen%16);
    printHex(packet->smolcert,packet->smolcertLen);

    err = readLVBlock(readPtr, packetLen-(readBytes-SC_TYPE_LEN-SC_PACKET_LEN_LEN), &packet->payload, &packet->payloadLen);
    if(err != SC_OK) {
        return err;
    }
    readPtr += (packet->payloadLen+2);
    readBytes += (packet->payloadLen+2);
    
    printf("Got remote payload@ %d bytes read\n",readBytes);
    printf("Remotelen: %d, unpadded len:%d\n",packet->payloadLen,packet->payloadLen-packet->payloadLen%16);
    printHex(packet->payload,packet->payloadLen);
    
    return err;
}


sc_err_t packHandshakeFin(sc_handshakeFinPacket* packet , sn_msg_t *msg){
    uint16_t packetLen;
    uint8_t version = SC_VERSION;
    uint8_t* writePtr;

    if(packet->HandshakeType != HANDSHAKE_FIN) return SC_PAKET_ERR;
    packetLen = SC_TYPE_LEN + SC_PACKET_LEN_LEN +SC_ID_LENGTH_LEN + packet->encryptedIdentityLen + packet->encryptedPayloadLen ;
    
    msg->msgLen = (size_t)packetLen;
    msg->msgBuf = (uint8_t*)malloc(msg->msgLen);
    writePtr = msg->msgBuf;

    memcpy(writePtr,&(packet->HandshakeType),SC_TYPE_LEN);
    writePtr += SC_TYPE_LEN;

    *writePtr = ((packetLen-3)&0x00FF);
    writePtr++;
    *writePtr = ((packetLen-3)&0xFF00)>>8;
    writePtr++;
    
    *writePtr = (packet->encryptedIdentityLen&0x00FF);
    writePtr++;
    *writePtr = (packet->encryptedIdentityLen&0xFF00)>>8;
    writePtr++;
    memcpy(writePtr,packet->encryptedIdentity,packet->encryptedIdentityLen);


    *writePtr = (packet->encryptedPayloadLen&0x00FF);
    writePtr++;
    *writePtr = (packet->encryptedPayloadLen&0xFF00)>>8;
    memcpy(writePtr,packet->encryptedPayload,packet->encryptedPayloadLen);
    //uint16_t lvBlockWritten;
    //writeLVBlock(writePtr, msg->msgLen - 3, packet->encryptedPayload, packet->encryptedPayloadLen, &lvBlockWritten);
    //writePtr += lvBlockWritten;

    // TODO prepare for additional payload
    
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
