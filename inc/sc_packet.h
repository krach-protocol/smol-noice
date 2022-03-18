#ifndef _SC_MESSAGE_H_
#define _SC_MESSAGE_H_

#include <inttypes.h>
#include <stdlib.h>

#include "sn_err.h"
#include "sn_buffer.h"

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
    sn_buffer_t*        smolcert;
    sn_buffer_t*        payload;
} sn_handshake_response_packet;

//HandshakeFin Client -> Server
typedef struct{
    sn_packet_type_e    HandshakeType;
    sn_buffer_t*        encrypted_identity;
    sn_buffer_t*        encrypted_payload;
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
sc_err_t pack_handshake_init(sn_handshake_init_packet* packet, sn_buffer_t *msg);

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

#endif