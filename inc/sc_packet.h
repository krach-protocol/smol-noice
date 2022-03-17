#ifndef _SC_MESSAGE_H_
#define _SC_MESSAGE_H_

#include <inttypes.h>
#include <stdlib.h>

#include "sn_err.h"
#include "sn_msg.h"

// length in bytes
#define SN_PACKET_LEN_LEN          2
#define SN_ID_LENGTH_LEN           2
#define SN_VERSION_LEN             1
#define SN_TYPE_LEN                1
#define SN_EPHEMERAL_PUB_KEY_LEN   32
#define SN_MAX_PACKET_LEN          512 //set at runtime

#define SN_VERSION                 0x01

typedef enum{HANDSHAKE_INIT=0x01,HANDSHAKE_RESPONSE=0x02,HANDSHAKE_FIN=0x03,TRANSPORT=0x10} sn_packet_type_e;

//HandshakeInit Client -> Server
typedef struct{ 
    sn_packet_type_e    HandshakeType;
    uint8_t*            ephemeralPubKey;
} sn_handshake_init_packet;

//HandshakeResponse Server -> Client
typedef struct{
    sn_packet_type_e    HandshakeType;
    uint8_t*            ephemeralPubKey;
    uint16_t            smolcertLen;
    uint8_t*            smolcert;
    uint16_t            payloadLen;
    uint8_t*            payload;
} sn_handshake_response_packet;

//HandshakeFin Client -> Server
typedef struct{
    sn_packet_type_e    HandshakeType;
    uint16_t            encryptedIdentityLen;
    uint8_t*            encryptedIdentity;
    uint16_t            encryptedPayloadLen;
    uint8_t*            encryptedPayload;
} sn_handshake_fin_packet;

//Transport Server <-> Client
typedef struct{
    sn_packet_type_e    PaketType;
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
sc_err_t pack_handshake_init(sn_handshake_init_packet* packet, sc_buffer_t *msg);

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
sc_err_t pack_handshake_fin(sn_handshake_fin_packet* packet, sn_buffer_t* buf);

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
sc_err_t unpack_handshake_response(sn_handshake_response_packet* packet, sn_buffer_t *msg);



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

void sn_write_uint16(uint8_t* buf, uint16_t val);

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