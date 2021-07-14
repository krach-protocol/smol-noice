#ifndef _SC_MESSAGE_H_
#define _SC_MESSAGE_H_

#include <inttypes.h>
#include <stdlib.h>

#include "sc_err.h"
#include "sn_msg.h"

typedef enum{HANDSHAKE_INIT=0x01,HANDSHAKE_RESPONSE=0x02,HANDSHAKE_FIN=0x03,TRANSPORT=0x10} sc_packet_type_e;

//HandshakeInit Client -> Server
typedef struct{ 
    sc_packet_type_e    HandshakeType;
    uint8_t*            ephemeralPubKey;
} sc_handshakeInitPacket;

//HandshakeResponse Server -> Client
typedef struct{
    sc_packet_type_e    HandshakeType;
    uint8_t*            ephemeralPubKey;
    uint16_t            smolcertLen;
    uint8_t*            smolcert;
    uint16_t            payloadLen;
    uint8_t*            payload;
} sc_handshakeResponsePacket;

//HandshakeFin Client -> Server
typedef struct{
    sc_packet_type_e    HandshakeType;
    uint16_t            encryptedIdentityLen;
    uint8_t*            encryptedIdentity;
    uint16_t            encryptedPayloadLen;
    uint8_t*            encryptedPayload;
} sc_handshakeFinPacket;

//Transport Server <-> Client
typedef struct{
    sc_packet_type_e    PaketType;
    uint8_t             encryptedPayloadLen;
    uint8_t*            encryptedPayload;
} sc_transportPacket;

/**
 * Function: packHandshakeInit
 * -----------------
 * Packs handshake init message for network transport, handles memory allocation for itself
 * 
 *  packet:       pointer to prefilled handshakeInit struct  
 *  msgBuffer:    pointer to uint8 array which is allocated in this function
 *  msgLen:       contains the length of msgBuffer
 *  return sc_err_t, SC_PAKET_ERR if something went wrong else SC_OK 
 * */
sc_err_t packHandshakeInit(sc_handshakeInitPacket* packet, sn_msg_t *msg);

/**
 * Function: packHandshakeFin
 * -----------------
 * Packs handshake fin message for network transport, handles memory allocation for itself
 * 
 *  packet:       pointer to prefilled handshakeFin struct  
 *  msgBuffer:    pointer to uint8 array which is allocated in this function
 *  msgLen:       contains the length of msgBuffer
 *  return sc_err_t, SC_PAKET_ERR if something went wrong else SC_OK 
 * */
sc_err_t packHandshakeFin(sc_handshakeFinPacket* packet ,sn_msg_t *msg);

/**
 * Function: unpackHandshakeResponse
 * -----------------
 * Unpacks handshakeResponse from network transport, handles memory allocation for itself, stores results in struct
 * 
 *  packet:       pointer to handshake response struct  
 *  msgBuffer:    pointer to uint8 array from network
 *  msgLen:       contains the length of msgBuffer
 *  return sc_err_t, SC_PAKET_ERR if something went wrong else SC_OK 
 * */
sc_err_t unpackHandshakeResponse(sc_handshakeResponsePacket* packet, sn_msg_t *msg);



/**
 * Function: readUint16
 * ---------------
 * Reads a little endian unsigned 16 bit integer from the provided buf. Calling functions must ensure that
 * the buffer contains at least 2 bytes.
 * 
 * buf:         Pointer to the byte array to read the uint16 from
 * return uint16_t, the little endian unsigned 16 bit integer
 * */
uint16_t readUint16(uint8_t* buf);

void writeUint16(uint8_t* buf, uint16_t val);

/**
 * Function: readLVBlock
 * ---------------------
 * Read a Length Value block. These are length prefixed blocks with the value following directly after.
 * It is assumed that the length is encoded as little endian unsigned 16 bit integer in the first two bytes.
 * 
 * buf:             Pointer to the byte array to read the LV block from
 * bufLen:          Total length of the byte array
 * dst:             Target pointer which holds the allocated memory for the read value
 * dstlen:          Length of the allocated destination byte array
 * return sc_err_t, SC_ERR if something went wrong otherwise SC_OK
 * */
sc_err_t readLVBlock(uint8_t* buf, uint16_t bufLen, uint8_t** dst, uint16_t *dstlen);

sc_err_t writeLVBlock(uint8_t *buf, uint16_t bufLen, uint8_t *data, uint16_t dataLen, uint16_t *outLen);



#endif