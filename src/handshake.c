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


void printHex(uint8_t*,uint8_t);
void printExpecedAction(NoiseHandshakeState *handshakeState);



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
    NoiseProtocolId krach = {0};//= (NoiseProtocolId*)malloc(sizeof(NoiseProtocolId));
    task_data_t *taskData = (task_data_t*)malloc(sizeof(task_data_t));
    int noiseErr = 0;
    char errBuf[32];

    krach.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach.dh_id = NOISE_DH_CURVE25519;
    krach.hash_id = NOISE_HASH_BLAKE2s;
    //krach.hybrid_id = NULL;
    krach.pattern_id = NOISE_PATTERN_XX;
    krach.prefix_id = NOISE_PREFIX_KRACH;
    //krach.reserved = {0};
     

    if((noiseErr = noise_handshakestate_new_by_id(&handshakeState,&krach,NOISE_ROLE_INITIATOR)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    krach->cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach->dh_id = NOISE_DH_CURVE25519;
    krach->hash_id = NOISE_HASH_BLAKE2s;
    krach->pattern_id = NOISE_PATTERN_XX;
    krach->prefix_id = NOISE_PREFIX_KRACH;
    err = noise_handshakestate_new_by_id(&handshakeState,krach,NOISE_ROLE_INITIATOR);
    
    if (err != NOISE_ERROR_NONE) {
        noise_perror(NULL, err);
           return SC_ERR;
    }  

    //set up ephmeral keypair
    // Set up local keypair 
    //dhState = noise_handshakestate_get_local_keypair_dh(handshakeState);
    dhState = handshakeState->dh_local_ephemeral;
   
    if(noise_handshakestate_get_fixed_ephemeral_dh(handshakeState) == NULL) printf("Doesnt have ephemeral key!");
    //if(noise_dhstate_set_role(dhState,NOISE_ROLE_INITIATOR) != NOISE_ERROR_NONE) return SC_ERR;	
    //TODO: Seed system RNG 

    if((noiseErr = noise_dhstate_generate_keypair(dhState)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }


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
    int noiseErr = 0;
    char errBuf[32];
    
    dhState = handshakeState->dh_local_ephemeral;
    pubKeyLen = noise_dhstate_get_public_key_length(dhState);
    pubKey = (uint8_t*)malloc(pubKeyLen);
    
    if((noiseErr = noise_dhstate_get_public_key(dhState,pubKey,pubKeyLen)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }
    
    packet->ephemeralPubKey = (uint8_t*)malloc(pubKeyLen);
    memcpy(packet->ephemeralPubKey,pubKey,pubKeyLen);

    
    if((noiseErr = noise_symmetricstate_mix_hash(symmState,pubKey,pubKeyLen)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

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
                printf("State: INIT NETWORK\n");
                if(openSocket(taskData->addr, taskData->port) == 0){
                    printf("Init ok\n");
                    currentStep = SEND_INIT;
                }else{
                    printf("error initialing socket\n");
                    currentStep = ERROR;
                }
            break;

            case SEND_INIT:
                printf("State: SEND INIT\n");
                sc_err = writeMessageE(handshakeState,&initPaket);

                initPaket.HandshakeType = HANDSHAKE_INIT;
                if(sc_err == SC_OK) sc_err = packHandshakeInit(&initPaket,&networkMsg);
                
                if(sc_err == SC_OK) sendOverNetwork(&networkMsg);

                if(sc_err != SC_OK){
                    currentStep = ERROR;
                }else{
                    currentStep = WAIT_FOR_RES;
                }
            break;    

            case WAIT_FOR_RES:
                printf("State: WAIT FOR RESPONSE\n");
                if(messageFromNetwork(&networkMsg)){
                    sc_err = unpackHandshakeResponse(&responsePaket,&networkMsg);

                    if(sc_err == SC_OK) sc_err = readMessageE_DHEE_S_DHES(handshakeState, &responsePaket); 
                    
                    if(sc_err != SC_OK){
                        currentStep = ERROR;
                    }else{
                        currentStep = SEND_FIN;
                    } 
                 }
            break;     

            case SEND_FIN:
                printf("State: SEND FINISH\n");
                sc_err = writeMessageS_DHSE(handshakeState, &finPaket);

                finPaket.HandshakeType = HANDSHAKE_FIN;
                
                
                if(sc_err == SC_OK) sc_err = packHandshakeFin(&finPaket,&networkMsg);

                if(sc_err == SC_OK) sendOverNetwork(&networkMsg);

                if(sc_err != SC_OK){
                    currentStep = ERROR;
                }else{
                    currentStep = DO_TRANSPORT;
                }
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


sc_err_t writeMessageS(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseBuffer buff;
    noise_buffer_init(buff);
    int noiseErr = 0;
    char errBuf[32];
    
        //TODO A lot of sanity checks missing here
        // check if local pub key is availible
        // and convert ed25519 key in curve25519 and add it to the dh state.
    


    // encryptedSPublic = s.symmState.EncryptAndHash(encryptedSPublic, idBytes) <-- is this right?
	// msg.WriteEncryptedIdentity(encryptedSPublic)

     if((noiseErr = noise_symmetricstate_encrypt_and_hash(symmState,&buff) != NOISE_ERROR_NONE)){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    memcpy(&packet->encryptedPayload,&buff.data,buff.size);
    packet->encryptedPayloadLen = buff.size;
    packet->HandshakeType = HANDSHAKE_FIN;
    
    return SC_OK;
}

sc_err_t writeMessageDHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    //- s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.  ))
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    NoiseDHState *dhStateRemoteEphemeral, *dhStateLocalPrivate;
    NoiseCipherState *sendCipher, *receiveCipher;
    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;
    int noiseErr = 0;
    char errBuf[32];

    dhStateRemoteEphemeral = noise_handshakestate_get_remote_public_key_dh(handshakeState); 
    dhStateLocalPrivate = noise_handshakestate_get_local_keypair_dh(handshakeState);
   
    if((noiseErr =  noise_dhstate_calculate(dhStateRemoteEphemeral,dhStateLocalPrivate,DHresult,DHresultSize)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    if((noiseErr = noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    //split symmetric state for encrypt(first cipher) and decrypt(second cipher)

    //see: http://rweather.github.io/noise-c/group__symmetricstate.html#gadf7cef60a64aef703add9b093c3b6c63

    if(noise_symmetricstate_split(symmState,&sendCipher,&receiveCipher) != NOISE_ERROR_NONE ) return SC_ERR;	

    return SC_OK;
}

sc_err_t writeMessageS_DHSE(NoiseHandshakeState *handshakeState, sc_handshakeFinPacket* packet){
    writeMessageS(handshakeState, packet);
    writeMessageDHSE(handshakeState, packet); 

    //TODO: encrypt identity and payload
    packet->encryptedIdentity = NULL;
    packet->encryptedIdentityLen = 0;
    packet->encryptedPayload = NULL;
    packet->encryptedPayloadLen = 0;
    
    return SC_OK;
}



// Read operations
sc_err_t readMessageE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //TODO Sanity checks missing here
    //s.remoteEphemeralPubKey, err = msg.ReadEPublic()
	//s.symmState.MixHash(s.remoteEphemeralPubKey[:])
    
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    if(noise_symmetricstate_mix_hash(symmState,packet->ephemeralPubKey,32)!= NOISE_ERROR_NONE) return SC_ERR;
    
    return SC_OK;
}

sc_err_t readMessageDHEE(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteEphemeralPubKey))

    //NoiseDHState *localKeypair = noise_handshakestate_get_fixed_ephemeral_dh(handshakeState); //TODO: Really?
    NoiseDHState *localKeypair = handshakeState->dh_local_ephemeral;//noise_handshakestate_get_local_keypair_dh(handshakeState); //TODO: Really?
    NoiseDHState *remoteEPPK = noise_handshakestate_get_remote_public_key_dh(handshakeState); //TODO: Really?
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    int noiseErr = 0;
    char errBuf[32];

    printf("private key len: %ld\n",noise_dhstate_get_private_key_length(localKeypair));
    if(noise_handshakestate_has_local_keypair(handshakeState) == 1) printf("Has local keypair\n");

    if((noiseErr = noise_dhstate_set_public_key(remoteEPPK, packet->ephemeralPubKey, 32)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    printf("Calculating DH state\n");
    if((noiseErr = noise_dhstate_calculate(localKeypair,remoteEPPK,DHresult,DHresultSize)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    } 

    printHex(DHresult,DHresultSize);

    printf("Mixing keys\n");
    if((noiseErr = noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }
    return SC_OK;
}

sc_err_t readMessageS(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
     NoiseDHState* remotePubKeyDH = NULL;
     uint8_t remotePubKey[32];
     smolcert_t remoteCert = {0};

    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;
    int noiseErr = 0;
    char errBuf[32];

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
    NoiseBuffer decryptedCertBuffer;
    uint8_t* decryptedCert= (uint8_t*)malloc(packet->smolcertLen);
   printf("Payload len: %d",packet->smolcertLen);
   printHex(packet->smolcert,packet->smolcertLen);


   noise_buffer_init(idBuffer);
   noise_buffer_init(decryptedCertBuffer);
   noise_buffer_set_input(idBuffer, packet->smolcert,packet->smolcertLen);
   noise_buffer_set_output(decryptedCertBuffer, decryptedCert,packet->smolcertLen);
   
    printf("Decrypting cert\n");

   if((noiseErr = noise_symmetricstate_decrypt_and_hash(symmState,&idBuffer)) != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    } 
    printf("Decrypted cert\n");
    printHex(decryptedCert,packet->smolcertLen);

   //TODO: write pad and unpad function for certBuffer
   
   //now idBuffer should contain a the server smolcert - go and validate
   // also we need to convert the ed25519 to curve25519, see krach -> smolcert.go:16
   // Need to add received pub key somehow to dhstate...

    printf("Parsing remote cert...\n");
    //printf("smolcert: %s\n",packet->smolcert);

    if(sc_parse_certificate(packet->smolcert,packet->smolcertLen, &remoteCert) != SC_OK) return SC_ERR;

    printf("Remote pubkey: %s \n",(char*)remoteCert.public_key);    
    if(sc_validate_certificate_signature(packet->smolcert, packet->smolcertLen, remoteCert.public_key) != SC_OK) return SC_ERR;

    //TODO: merge get_curve in master branch or checkout dev-branch
    if(sc_get_curve_public_key(&remoteCert,remotePubKey) != SC_OK) return SC_ERR;

   //See: http://rweather.github.io/noise-c/group__handshakestate.html#ga1e34b02757ddef3481caccf85c9a1d54
    remotePubKeyDH = noise_handshakestate_get_remote_public_key_dh(handshakeState);
    if(remotePubKeyDH == NULL) return SC_ERR;

    //See: http://rweather.github.io/noise-c/group__dhstate.html#gac6fa00b45a6db3bb405ed1163e09ae95
    if(NOISE_ERROR_NONE != noise_dhstate_set_public_key(remotePubKeyDH,remotePubKey,32)) return SC_ERR;

    
    //TODO: perform some black magic on handShakeState
    NoiseDHState *dhStateLocalPrivate = noise_handshakestate_get_local_keypair_dh(handshakeState);
    
    noise_dhstate_calculate(dhStateLocalPrivate,remotePubKeyDH,DHresult,DHresultSize);
    noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize);


   return SC_OK;
}

sc_err_t readMessageDHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    //s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()));
    NoiseDHState *remotePKDH = noise_handshakestate_get_remote_public_key_dh(handshakeState); // If we set the remote pubkey correctly in readMessageS, this should work as expected
    NoiseDHState *localFEDH = noise_handshakestate_get_fixed_ephemeral_dh(handshakeState); //TODO: Really?
    NoiseSymmetricState *symmState = handshakeState->symmetric;
    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;

    noise_dhstate_calculate(localFEDH,remotePKDH,DHresult,DHresultSize);
    noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize);
    return SC_OK;
}
sc_err_t readMessageE_DHEE_S_DHES(NoiseHandshakeState *handshakeState, sc_handshakeResponsePacket *packet){
    if(readMessageE(handshakeState, packet) != SC_OK) return SC_ERR;
    if(readMessageDHEE(handshakeState, packet) != SC_OK) return SC_ERR;
    if(readMessageS(handshakeState, packet) != SC_OK) return SC_ERR;
    if(readMessageDHES(handshakeState, packet) != SC_OK) return SC_ERR;
    return SC_OK;
}



void printExpecedAction(NoiseHandshakeState *handshakeState){

}