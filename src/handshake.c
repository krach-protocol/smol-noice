#include "handshake.h"

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <noise/protocol.h>

#include "smolcert.h"
#include "port.h"
#include "sc_packet.h"
#include "sn_msg.h"


typedef enum{INIT_NETWORK,SEND_INIT,WAIT_FOR_RES,SEND_FIN,DO_TRANSPORT,ERROR} handshakeSteps;

//Internal struct for throwing data at worker task
typedef struct {
    char* addr;
    uint16_t port;
    smolcert_t* clientCert;
    smolcert_t *rootCert;
    remoteCertCb_t certCallback;
    newTransportCb_t transportCallback;
    NoiseHandshakeState* handshake;
} task_data_t;


//Internal functions
sc_err_t writeMessageE(NoiseHandshakeState *handshakeState,sc_handshakeInitPacket* packet);

sc_err_t writeMessageS_DHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet);
sc_err_t writeMessageS(NoiseHandshakeState *handshakeState,sc_handshakeFinPacket* packet);
sc_err_t writeMessageDHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet);

sc_err_t readMessageE_DHEE_S_DHES(NoiseHandshakeState *handshakeState,sc_handshakeResponsePacket *packet);
sc_err_t readMessageE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet);
sc_err_t readMessageDHEE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet);
sc_err_t readMessageS(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet);
sc_err_t readMessageDHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet);

void* runnerTask(void* arg);


void printHex(uint8_t*,uint8_t);
void printCryptoData(NoiseHandshakeState *handshakeState);


//Error Utils
sc_err_t printNoiseErr(int);
#define NOISE_ERROR_CHECK(error) \
    if(printNoiseErr(error) != SC_OK) return SC_ERR;


/**
 * Since we know this implementation is fully based on the krach-protocol and is only used as
 * a client-implementation we can skip a lot of checks from the echo-tutorial (http://rweather.github.io/noise-c/example_echo.html)
 * 
 *  Nice function for all sanity checks: noise_handshakestate_get_action 
 *  http://rweather.github.io/noise-c/group__symmetricstate.html
 * 
 * 
 * 
*/


sc_err_t sc_init(   smolcert_t *clientCert,
                    smolcert_t *rootCert,
                    remoteCertCb_t certCallback,
                    newTransportCb_t transportCallback,
                    const char *addr,
                    uint16_t port)
    {
    int err;
    sc_err_t sc_err;
    NoiseDHState* localEphemeralKeypair = NULL; 
    NoiseHandshakeState *handshakeState;
    NoiseProtocolId krach = {0};
    task_data_t *taskData = (task_data_t*)malloc(sizeof(task_data_t));
    int noiseErr = 0;
    char errBuf[32];

    krach.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach.dh_id = NOISE_DH_CURVE25519;
    krach.hash_id = NOISE_HASH_BLAKE2s;
    krach.pattern_id = NOISE_PATTERN_XX;
    krach.prefix_id = NOISE_PREFIX_KRACH;
     

    NOISE_ERROR_CHECK(noise_handshakestate_new_by_id(&handshakeState,&krach,NOISE_ROLE_INITIATOR));

    //set up ephmeral keypair
    //TODO: Seed system RNG 
    localEphemeralKeypair = handshakeState->dh_local_ephemeral;
    NOISE_ERROR_CHECK(noise_dhstate_generate_keypair(localEphemeralKeypair));
   

    //TODO: Implement platform agnostic Taskstarter
    taskData->addr = (char*)malloc(strlen(addr));
    strcpy(taskData->addr,addr);
    taskData->port = port;
    taskData->clientCert = clientCert;
    taskData->rootCert = rootCert;
    taskData->certCallback = certCallback;
    taskData->transportCallback = transportCallback;
    taskData->handshake = handshakeState;
    
    startTask(&runnerTask,(void*)taskData);    

    return SC_OK;
}


sc_err_t sc_destroy(NoiseHandshakeState *handshakeState){
    noise_handshakestate_free(handshakeState);
    return SC_OK;
}



void* runnerTask(void* arg){
    task_data_t *taskData = (task_data_t*) arg;
    bool run = true;
    sc_err_t sc_err;
    handshakeSteps currentStep = INIT_NETWORK;
    NoiseHandshakeState *handshakeState = taskData->handshake;

    sc_handshakeInitPacket     initPaket={0};
    sc_handshakeResponsePacket responsePaket={0};
    sc_handshakeFinPacket      finPaket={0};

    sn_msg_t networkMsg = {0};
    printf("Starting main loop\n");
    while(run){
        sleep_ms(500);
        switch(currentStep){
            case INIT_NETWORK:
                printf("State: INIT NETWORK\n");
                if(openSocket(taskData->addr, taskData->port) == 0){
                    currentStep = SEND_INIT;
                }else{
                    printf("error initialing socket\n");
                    currentStep = ERROR;
                }
            break;

            case SEND_INIT:
                printf("State: SEND INIT\n");
                
                STATE_ERROR_CHECK(writeMessageE(handshakeState,&initPaket));
                initPaket.HandshakeType = HANDSHAKE_INIT;
               
                STATE_ERROR_CHECK(packHandshakeInit(&initPaket,&networkMsg));
                sendOverNetwork(&networkMsg);
                currentStep = WAIT_FOR_RES;
            break;    

            case WAIT_FOR_RES:
                printf("State: WAIT FOR RESPONSE\n");
                if(messageFromNetwork(&networkMsg)){
                    STATE_ERROR_CHECK(unpackHandshakeResponse(&responsePaket,&networkMsg));
                    STATE_ERROR_CHECK(readMessageE_DHEE_S_DHES(handshakeState, &responsePaket));

                    currentStep = SEND_FIN;
                 }
            break;     

            case SEND_FIN:
                printf("State: SEND FINISH\n");

                STATE_ERROR_CHECK(writeMessageS_DHSE(handshakeState, &finPaket));

                finPaket.HandshakeType = HANDSHAKE_FIN;
                STATE_ERROR_CHECK(packHandshakeFin(&finPaket,&networkMsg));
                
                sendOverNetwork(&networkMsg);
                currentStep = DO_TRANSPORT;
            break;            
             
            case DO_TRANSPORT:
                printf("State: DO TRANSPORT\n");
                //if(messageFromNetwork)
                //unpackTransport
                //decrypt
                //putInRxQueue
                //
                //if(messageInLocalTxQueue)
                //encrypt
                //packTransport
                //sendOverNetwork
            break;    

            case ERROR: 
                printf("Error in Handshake - abort\n");
                run = false;
            break;        

            default:
                //wat?
            break;
    }
}
return NULL;
}


sc_err_t writeMessageE(NoiseHandshakeState *handshakeState,sc_handshakeInitPacket* packet){
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseDHState *dhState;   
    size_t pubKeyLen;
    uint8_t* pubKey;
    int noiseErr = 0;
    char errBuf[32];
    
    dhState = handshakeState->dh_local_ephemeral;
    pubKeyLen = noise_dhstate_get_public_key_length(dhState);
    pubKey = (uint8_t*)malloc(pubKeyLen);
    
    NOISE_ERROR_CHECK(noise_dhstate_get_public_key(dhState,pubKey,pubKeyLen));
    
    packet->ephemeralPubKey = (uint8_t*)malloc(pubKeyLen);
    memcpy(packet->ephemeralPubKey,pubKey,pubKeyLen);

    NOISE_ERROR_CHECK(noise_symmetricstate_mix_hash(symmState,pubKey,pubKeyLen));

    free(pubKey);
   	return SC_OK;
}

sc_err_t writeMessageS(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseBuffer buff;
    noise_buffer_init(buff);
    int noiseErr = 0;
    char errBuf[32];
    

    //Padded smolcert in buffer
    //IMPORTANT: Buffersize: n byte smolcert + 16byte MAC + padding%16 (1-15byte)
    //prepend number of appended bytes(prepended byte not included)
    //encrypt identity inplace?

    NOISE_ERROR_CHECK(noise_symmetricstate_encrypt_and_hash(symmState,&buff));

    memcpy(&packet->encryptedIdentity,&buff.data,buff.size);
    packet->encryptedIdentityLen = buff.size;
    packet->HandshakeType = HANDSHAKE_FIN;
    
    return SC_OK;
}

sc_err_t writeMessageDHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseDHState *remoteStaticKeypair, *localEphemeralKeypair;
    NoiseCipherState *sendCipher, *receiveCipher;
    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;
    int noiseErr = 0;
    char errBuf[32];

    remoteStaticKeypair = noise_handshakestate_get_remote_public_key_dh(handshakeState); 
    localEphemeralKeypair = handshakeState->dh_local_ephemeral;
   
    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteStaticKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));
    

    //split symmetric state for encrypt(first cipher) and decrypt(second cipher)
    //see: http://rweather.github.io/noise-c/group__symmetricstate.html#gadf7cef60a64aef703add9b093c3b6c63
    NOISE_ERROR_CHECK(noise_symmetricstate_split(symmState,&sendCipher,&receiveCipher));
    //NOTE: possibly noise-c handles this for itself

    return SC_OK;
}

sc_err_t writeMessageS_DHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    SC_ERROR_CHECK(writeMessageS(handshakeState, packet));
    SC_ERROR_CHECK(writeMessageDHSE(handshakeState, packet));
    

    //TODO: encrypt identity and payload
    //TODO: Provide access to local identity here
    packet->encryptedIdentity = NULL;
    packet->encryptedIdentityLen = 0;
    packet->encryptedPayload = NULL;
    packet->encryptedPayloadLen = 0;
    
    return SC_OK;
}



// Read operations
sc_err_t readMessageE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){    
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseDHState *remoteEphemeralKeypair = handshakeState->dh_remote_ephemeral;


    NOISE_ERROR_CHECK(noise_dhstate_set_public_key(remoteEphemeralKeypair, packet->ephemeralPubKey, 32));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_hash(symmState,packet->ephemeralPubKey,32));
    
    return SC_OK;
}

sc_err_t readMessageDHEE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    NoiseDHState *localEphemeralKeypair = handshakeState->dh_local_ephemeral;
    NoiseDHState *remoteEphemeralKeypair = handshakeState->dh_remote_ephemeral;
    NoiseSymmetricState *symmState = handshakeState->symmetric;

    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    int noiseErr = 0;
    char errBuf[32];

    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteEphemeralKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}

sc_err_t readMessageS(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
     NoiseDHState* remoteStaticKeypair = NULL;
     uint8_t remotePubKey[32];
     smolcert_t remoteCert = {0};

    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;
    int noiseErr = 0;
    char errBuf[32];

   NoiseSymmetricState *symmState = handshakeState->symmetric;
   NoiseBuffer idBuffer;
    
   
   noise_buffer_init(idBuffer);
   noise_buffer_set_input(idBuffer, packet->smolcert,packet->smolcertLen);
   
   NOISE_ERROR_CHECK(noise_symmetricstate_decrypt_and_hash(symmState,&idBuffer));
   

    uint8_t paddedBytes = packet->smolcert[0];
    uint8_t smolCertEnd = packet->smolcertLen - 16 - paddedBytes;
    //printf("Padded bytes: %d\n",paddedBytes);
    packet->smolcert+= 1;
    packet->smolcert[smolCertEnd] = '\0';  
    //TODO: write pad and unpad function for certBuffer

   

    SC_ERROR_CHECK(sc_parse_certificate(packet->smolcert,packet->smolcertLen, &remoteCert));
    
    uint8_t rootPubKey[32] = {
        0x65,0x2F,0x0E,0x9B,0x6A,0x0F,0xA2,0x5E,0xD3,0x25,0x19,0xC9,0x19,0x73,0x99,0x64,
        0x58,0xFC,0x58,0x32,0xA5,0x9B,0xAC,0x55,0xEA,0xED,0xF4,0x65,0xA0,0x5B,0x75,0xCB};
    //TODO implement callback for cert handling
    
    //TODO check why validation fails
    //if(sc_validate_certificate_signature(packet->smolcert, packet->smolcertLen, rootPubKey) != SC_OK) return SC_ERR;
    

    SC_ERROR_CHECK(sc_get_curve_public_key(&remoteCert,remotePubKey));
    
    //Finally set the public Key
    remoteStaticKeypair = noise_handshakestate_get_remote_public_key_dh(handshakeState);
    if(remoteStaticKeypair == NULL) return SC_ERR;
    NOISE_ERROR_CHECK(noise_dhstate_set_public_key(remoteStaticKeypair,remotePubKey,32))

    
   return SC_OK;
}

sc_err_t readMessageDHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    NoiseDHState *remoteStaticKeypair = handshakeState->dh_remote_static; 
    NoiseDHState *localEphemeralKeypair = handshakeState->dh_local_ephemeral; 
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteStaticKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}
sc_err_t readMessageE_DHEE_S_DHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    
    SC_ERROR_CHECK(readMessageE(handshakeState, packet));
    SC_ERROR_CHECK(readMessageDHEE(handshakeState, packet));
    SC_ERROR_CHECK(readMessageS(handshakeState, packet));
    SC_ERROR_CHECK(readMessageDHES(handshakeState, packet));
    return SC_OK;
}



void printCryptoData(NoiseHandshakeState *handshakeState){
    NoiseCipherState* cipher = handshakeState->symmetric->cipher;
    NoiseHashState* hash = handshakeState->symmetric->hash;
}

sc_err_t printNoiseErr(int noiseErr){
    char errBuf[32];

    if(noiseErr != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    return SC_OK;
}