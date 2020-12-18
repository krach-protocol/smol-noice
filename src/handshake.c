#include "handshake.h"
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <noise/protocol.h>

#include "sc_packet.h"

#define PROTOCOL "KRACH_XX_25519_CHACHAPOLY_BLAKE2S"


typedef enum{SEND_INIT,WAIT_FOR_RES,SEND_FIN,DO_TRANSPORT,ERROR} handshakeSteps;


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


//sc_err_t sc_init(mySmolCert,targetIp);
sc_err_t sc_init(void){
    int err;
    sc_err_t sc_err;
    NoiseDHState* dhState; 
    handshakeSteps currentStep;

    NoiseHandshakeState *handshakeState;
    NoiseProtocolId *krach = (NoiseProtocolId*)malloc(sizeof(NoiseProtocolId));
    krach->cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach->dh_id = NOISE_DH_CURVE25519;
    krach->hash_id = NOISE_HASH_BLAKE2s;
    krach->pattern_id = NOISE_PATTERN_XX;
    krach->prefix_id = NOISE_PREFIX_NONE;

    err = noise_handshakestate_new_by_id(&handshakeState,krach,NOISE_ROLE_INITIATOR);
    

    err = NOISE_ERROR_NONE;
    if (err != NOISE_ERROR_NONE) {
        noise_perror(PROTOCOL, err);
        return SC_ERR;
    }   

    // Set up local keypair 
    dhState = noise_handshakestate_get_local_keypair_dh(handshakeState);
    if(noise_dhstate_set_role(dhState,NOISE_ROLE_INITIATOR) != NOISE_ERROR_NONE) return SC_ERR;	
    //TODO: Seed system RNG 
    if(noise_dhstate_generate_keypair(dhState) != NOISE_ERROR_NONE) return SC_ERR;	

    //This should ideally be a task/thread.
    currentStep = SEND_INIT;

    sc_handshakeInitPacket*     initPaket=NULL;
    sc_handshakeResponsePacket* responsePaket=NULL;
    sc_handshakeFinPacket*      finPaket=NULL;

    uint8_t*    networkPacket = NULL;
    size_t      networkPacketSize = 0;

    while(1){
        switch(currentStep){
            case SEND_INIT:
                sc_err = writeMessageE(handshakeState,initPaket);
                packHandshakeInit(initPaket,&networkPacket,&networkPacketSize);
                //sendOverNetwork(networkPacket,networkPacketSize)
                currentStep = WAIT_FOR_RES;
            break;    

            case WAIT_FOR_RES:
                // if(messageFromNetwork)
                 unpackHandshakeResponse(responsePaket,networkPacket,networkPacketSize);
                 sc_err = readMessageE_DHEE_S_DHES(handshakeState, responsePaket); 
                 currentStep = SEND_FIN;
            break;     

            case SEND_FIN:
                sc_err = writeMessageS_DHSE(handshakeState, finPaket);
                packHandshakeFin(finPaket,&networkPacket,&networkPacketSize);
                // sendOverNetwork(networkPacket,networkPacketSize)
                currentStep = DO_TRANSPORT;
            break;            
             
            case DO_TRANSPORT:
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
                // ???
            break;        

            default:
                //wat?
            break;            
        }
    }

    return SC_OK;
}


sc_err_t sc_destroy(NoiseHandshakeState handshakeState){
    noise_handshakestate_free(&handshakeState);
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
    
    if(noise_dhstate_get_public_key(dhState,pubKey,pubKeyLen) != NOISE_ERROR_NONE) return SC_ERR;
    
    memcpy(&(packet->ephemeralPubKey),pubKey,pubKeyLen);

    if(noise_symmetricstate_mix_hash(symmState,pubKey,pubKeyLen) != NOISE_ERROR_NONE) return SC_ERR;

    free(pubKey);
   	return SC_OK;
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

