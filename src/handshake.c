#include "handshake.h"

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <noise/protocol.h>


#include "port.h"
#include "sc_packet.h"
#include "sn_msg.h"

//#define PROTOCOL "KRACH_XX_25519_CHACHAPOLY_BLAKE2S"


typedef enum{INIT_NETWORK,SEND_INIT,WAIT_FOR_RES,SEND_FIN,DO_TRANSPORT,ERROR} handshakeSteps;

//Internal struct for throwing data at worker task
typedef struct {
    smolcert_t* cert;
    char* addr;
    uint16_t port;
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


sc_err_t sc_init(smolcert_t *cert,const char *addr,uint16_t port){
    int err;
    sc_err_t sc_err;
    NoiseDHState* dhState = NULL; 
    NoiseHandshakeState *handshakeState;// = (NoiseHandshakeState*)malloc(sizeof(NoiseHandshakeState));
    NoiseProtocolId *krach = (NoiseProtocolId*)malloc(sizeof(NoiseProtocolId));
    task_data_t *taskData = (task_data_t*)malloc(sizeof(task_data_t));

    krach->cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach->dh_id = NOISE_DH_CURVE25519;
    krach->hash_id = NOISE_HASH_BLAKE2s;
    krach->pattern_id = NOISE_PATTERN_XX;
    krach->prefix_id = NOISE_PREFIX_STANDARD;
    err = noise_handshakestate_new_by_id(&handshakeState,krach,NOISE_ROLE_INITIATOR);
    
    if (err != NOISE_ERROR_NONE) {
        noise_perror(NULL, err);
           return SC_ERR;
    }  

    //set up ephmeral keypair
    // Set up local keypair 
    dhState = noise_handshakestate_get_local_keypair_dh(handshakeState);
   
    //if(noise_dhstate_set_role(dhState,NOISE_ROLE_INITIATOR) != NOISE_ERROR_NONE) return SC_ERR;	
    //TODO: Seed system RNG 
    if(noise_dhstate_generate_keypair(dhState) != NOISE_ERROR_NONE) return SC_ERR;	


    //TODO: Implement platform agnostic Taskstarter
    taskData->addr = (char*)malloc(strlen(addr));
    strcpy(taskData->addr,addr);
    taskData->port = port;
    taskData->cert = cert;
    taskData->handshake = handshakeState;
    
    startTask(&runnerTask,(void*)taskData);    

    return SC_OK;
}


sc_err_t sc_destroy(NoiseHandshakeState *handshakeState){
    noise_handshakestate_free(handshakeState);
    return SC_OK;
}

sc_err_t writeMessageE(NoiseHandshakeState *handshakeState,sc_handshakeInitPacket* packet){
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseDHState *dhState;   
    size_t pubKeyLen;
    uint8_t* pubKey;
    
    dhState = noise_handshakestate_get_local_keypair_dh(handshakeState);
    pubKeyLen = noise_dhstate_get_public_key_length(dhState);
    pubKey = (uint8_t*)malloc(pubKeyLen);
    printf("PubKeylen: %ld\n",pubKeyLen);
    if(noise_dhstate_get_public_key(dhState,pubKey,pubKeyLen) != NOISE_ERROR_NONE) return SC_ERR;
    
    packet->ephemeralPubKey = (uint8_t*)malloc(pubKeyLen);
    memcpy(packet->ephemeralPubKey,pubKey,pubKeyLen);

    if(noise_symmetricstate_mix_hash(symmState,pubKey,pubKeyLen) != NOISE_ERROR_NONE) return SC_ERR;

    free(pubKey);
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
                printf("Init Network\n");
                if(openSocket(taskData->addr, taskData->port) == 0){
                    printf("Init ok\n");
                    currentStep = SEND_INIT;
                }else{
                    printf("error initialing socket\n");
                    currentStep = ERROR;
                }
            break;
            case SEND_INIT:
                printf("Send Init\n");
                sc_err = writeMessageE(handshakeState,&initPaket);
                packHandshakeInit(&initPaket,&networkMsg);
                sendOverNetwork(&networkMsg);
                currentStep = WAIT_FOR_RES;
            break;    

            case WAIT_FOR_RES:
                printf("Wait for response\n");
                 if(messageFromNetwork(&networkMsg)){
                    unpackHandshakeResponse(&responsePaket,&networkMsg);
                    sc_err = readMessageE_DHEE_S_DHES(handshakeState, &responsePaket); 
                    currentStep = SEND_FIN;
                 }
            break;     

            case SEND_FIN:
                printf("Send finish\n");
                sc_err = writeMessageS_DHSE(handshakeState, &finPaket);
                packHandshakeFin(&finPaket,&networkMsg);
                sendOverNetwork(&networkMsg);
                currentStep = DO_TRANSPORT;
            break;            
             
            case DO_TRANSPORT:
                printf("Do transport\n");
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


sc_err_t writeMessageS(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseBuffer buff;
    noise_buffer_init(buff);
    
        //TODO A lot of sanity checks missing here
        // check if local pub key is availible


    // encryptedSPublic = s.symmState.EncryptAndHash(encryptedSPublic, idBytes) <-- is this right?
	// msg.WriteEncryptedIdentity(encryptedSPublic)
    if( noise_symmetricstate_encrypt_and_hash(symmState,&buff) != NOISE_ERROR_NONE) return SC_ERR;

    memcpy(&packet->encryptedPayload,&buff.data,buff.size);
    packet->encryptedPayloadLen = buff.size;
    packet->HandshakeType = HANDSHAKE_FIN;
    
    return SC_OK;
}

sc_err_t writeMessageDHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    //- s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.  ))
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseDHState *dhStateRemoteEphemeral, *dhStateLocalPrivate;
    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;
   
    dhStateRemoteEphemeral = noise_handshakestate_get_remote_public_key_dh(handshakeState); // <-- is this the remote eph key?
    dhStateLocalPrivate = noise_handshakestate_get_local_keypair_dh(handshakeState); // wat?
   
    noise_dhstate_calculate(dhStateRemoteEphemeral,dhStateLocalPrivate,DHresult,DHresultSize);
    noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize);

    return SC_OK;
}

sc_err_t writeMessageS_DHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    writeMessageS(handshakeState, packet);
    writeMessageDHSE(handshakeState, packet); 
    return SC_OK;
}



// Read operations
sc_err_t readMessageE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //TODO Sanity checks missing here
    //s.remoteEphemeralPubKey, err = msg.ReadEPublic()
	//s.symmState.MixHash(s.remoteEphemeralPubKey[:])
    
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    noise_symmetricstate_mix_hash(symmState,packet->ephemeralPubKey,32);
    
    return SC_OK;
}

sc_err_t readMessageDHEE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteEphemeralPubKey))
    NoiseDHState *localFEDH = noise_handshakestate_get_fixed_ephemeral_dh(handshakeState); //TODO: Really?
    NoiseDHState *remoteEPPK = noise_handshakestate_get_remote_public_key_dh(handshakeState); //TODO: Really?
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;

    noise_dhstate_calculate(localFEDH,remoteEPPK,DHresult,DHresultSize);
    noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize);
    return SC_OK;
}

sc_err_t readMessageS(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //TODO Sanity checks missing here
    /* idBytes, err := msg.ReadEncryptedIdentity()
	var decryptedRawIdentity []byte
	decryptedRawIdentity, err = s.symmState.DecryptAndHash(decryptedRawIdentity, idBytes)

	smCrt, err := smolcert.ParseBuf(decryptedRawIdentity)
	identity := &Identity{*smCrt}
	if err := s.eventuallyVerifyIdentity(identity); err != nil {
		return fmt.Errorfl("Failed to verify remote identity: %w", err)
	}

	s.remoteIdentity = identity
    */
   NoiseSymmetricState *symmState = handshakeState->symmetric;
   NoiseBuffer idBuffer;
   noise_buffer_init(idBuffer);
   noise_buffer_set_input(idBuffer, packet->encryptedPayload,packet->encryptedPayloadLen);
   noise_symmetricstate_decrypt_and_hash(symmState,&idBuffer);
   
   //now idBuffer should contain a the server smolcert - go and validate
   return SC_OK;
}

sc_err_t readMessageDHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()));
    NoiseDHState *remotePKDH = noise_handshakestate_get_remote_public_key_dh(handshakeState);
    NoiseDHState *localFEDH = noise_handshakestate_get_fixed_ephemeral_dh(handshakeState); //TODO: Really?
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;

    noise_dhstate_calculate(localFEDH,remotePKDH,DHresult,DHresultSize);
    noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize);
    return SC_OK;
}
sc_err_t readMessageE_DHEE_S_DHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    readMessageE(handshakeState, packet);
    readMessageDHEE(handshakeState, packet);
    readMessageS(handshakeState, packet);
    readMessageDHES(handshakeState, packet);
    return SC_OK;
}