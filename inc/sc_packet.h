#ifndef _SC_MESSAGE_H_
#define _SC_MESSAGE_H_

#include <inttypes.h>
#include <stdlib.h>

#include "sc_err.h"

typedef enum{HANDSHAKE_INIT,HANDSHAKE_RESPONSE=0x02,HANDSHAKE_FIN,TRANSPORT} sc_packet_type_e;

//HandshakeInit Client -> Server
typedef struct{ 
    uint16_t            packetLen;
    uint8_t*            packetBuffer;
    sc_packet_type_e    HandshakeType;
    uint8_t*            ephemeralPubKey;
} sc_handshakeInitPacket;

//HandshakeResponse Server -> Client
typedef struct{
    uint16_t            packetLen;
    uint8_t*            packetBuffer;
    sc_packet_type_e    HandshakeType;
    uint8_t*            ephemeralPubKey;
    uint8_t             encryptedPayloadLen;
    uint8_t*            encryptedPayload;
} sc_handshakeResponsePacket;

//HandshakeFin Client -> Server
typedef struct{
    uint16_t            packetLen;
    uint8_t*            packetBuffer;
    sc_packet_type_e    HandshakeType;
    uint8_t             encryptedPayloadLen;
    uint8_t*            encryptedPayload;
} sc_handshakeFinPacket;

//Transport Server <-> Client
typedef struct{
    uint16_t            packetLen;
    uint8_t*            packetBuffer;
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
sc_err_t packHandshakeInit(sc_handshakeInitPacket* packet, uint8_t** msgBuffer, size_t* msgLen);

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
sc_err_t packHandshakeFin(sc_handshakeFinPacket* packet ,uint8_t** msgBuffer, size_t* msgLen);

/**
 * Function: packTransport
 * -----------------
 * Packs transport message for network transport, handles memory allocation for itself
 * 
 *  packet:       pointer to prefilled transport struct  
 *  msgBuffer:    pointer to uint8 array which is allocated in this function
 *  msgLen:       contains the length of msgBuffer
 *  return sc_err_t, SC_PAKET_ERR if something went wrong else SC_OK 
 * */
sc_err_t packTransport(sc_transportPacket* packet, uint8_t* msgBuffer, size_t* msgLen);


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
sc_err_t unpackHandshakeResponse(sc_handshakeResponsePacket* packet, uint8_t* msgBuffer, uint8_t msgLen);


/**
 * Function: unpackTransport
 * -----------------
 * Unpacks transport packet from network transport, handles memory allocation for itself, stores results in struct
 * 
 *  packet:       pointer to transport struct
 *  msgBuffer:    pointer to uint8 array from network
 *  msgLen:       contains the length of msgBuffer
 *  return sc_err_t, SC_PAKET_ERR if something went wrong else SC_OK 
 * */
sc_err_t unpackTransport(sc_transportPacket* packet, uint8_t* msgBuffer, size_t msgLen);





#endif