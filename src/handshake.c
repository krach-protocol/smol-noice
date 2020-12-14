#include "handshake.h"

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <noise/protocol.h>
//#include <noise/protocol/symmetricstate.h>
//#include <internal.h>

#define PROTOCOL "KRACH_XX_25519_CHACHAPOLY_BLAKE2S"

//Internal functions
sc_err_t writeMessageE(NoiseHandshakeState handshakeState,char* message);
sc_err_t writeMessageS_DHSE(NoiseHandshakeState handshakeState, char* message);
sc_err_t writeMessageS(NoiseHandshakeState handshakeState,char* message);
sc_err_t writeMessageDHSE(NoiseHandshakeState handshakeState, char* message);

sc_err_t readMessageE_DHEE_S_DHES(NoiseHandshakeState handshakeState,char* message);
sc_err_t readMessageE(NoiseHandshakeState handshakeState, char* message);
sc_err_t readMessageDHEE(NoiseHandshakeState handshakeState, char* message);
sc_err_t readMessageS(NoiseHandshakeState handshakeState, char* message);
sc_err_t readMessageDHES(NoiseHandshakeState handshakeState, char* message);



/**
 * Since we know this implementation is fully based on the krach-protocol and is only used as
 * a client-implementation we can skip a lot of checks from the echo-tutorial (http://rweather.github.io/noise-c/example_echo.html)
 * 
 *  Nice function for all sanity checks: noise_handshakestate_get_action 
 *  http://rweather.github.io/noise-c/group__symmetricstate.html
 * 
 * 
 * TODO: Implement own message type + handler
 * 
 * 
*/

sc_err_t sc_init(NoiseHandshakeState handshakeState){
    int err;
    NoiseDHState* dhState; 

    err = NOISE_ERROR_NONE;//((&handshakeState),PROTOCOL, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(PROTOCOL, err);
        return SC_ERR;
    }   

    // Set up local keypair 
    dhState = noise_handshakestate_get_local_keypair_dh(&handshakeState);
    if(noise_dhstate_set_role(dhState,NOISE_ROLE_INITIATOR) != NOISE_ERROR_NONE) return SC_ERR;	
    //TODO: Seed system RNG 
    if(noise_dhstate_generate_keypair(dhState) != NOISE_ERROR_NONE) return SC_ERR;	

    return SC_OK;
}


sc_err_t sc_destory(NoiseHandshakeState handshakeState){
    noise_handshakestate_free(&handshakeState);
    return SC_OK;
}

sc_err_t writeMessageE(NoiseHandshakeState handshakeState,char* message){
    NoiseDHState* dhState;   
    //struct NoiseHandshakeState_s test;
    NoiseSymmetricState *symmState = handshakeState.symmetric;
    size_t pubKeyLen;
    uint8_t* pubKey;
    
    dhState = noise_handshakestate_get_local_keypair_dh(&handshakeState);
    pubKeyLen = noise_dhstate_get_public_key_length(dhState);
    pubKey = (uint8_t*)malloc(pubKeyLen);
    
    if(noise_dhstate_get_public_key(dhState,pubKey,pubKeyLen) != NOISE_ERROR_NONE) return SC_ERR;
    
    if(strncat(message,pubKey,pubKeyLen) == NULL) return SC_ERR;

    if(noise_symmetricstate_mix_hash(symmState,pubKey,pubKeyLen) != NOISE_ERROR_NONE) return SC_ERR;

   	return SC_OK;
}


sc_err_t writeMessageS(NoiseHandshakeState handshakeState, char* message){
    NoiseSymmetricState symmState;
        //TODO A lot of sanity checks missing here


    // encryptedSPublic = s.symmState.EncryptAndHash(encryptedSPublic, idBytes)
    
    int noise_symmetricstate_encrypt_and_hash(NoiseSymmetricState *state,NoiseBuffer * 	buffer );

	// msg.WriteEncryptedIdentity(encryptedSPublic)
    return SC_OK;
}

sc_err_t writeMessageDHSE(NoiseHandshakeState handshakeState, char* message){
    //- s.symmState.MixKey(s.symmState.DH(s.localIdentity.PrivateKey(), s.remoteEphemeralPubKey))
    return SC_OK;
}

sc_err_t writeMessageS_DHSE(NoiseHandshakeState handshakeState, char* message){
    //writeMessageS(handshakeState, message)
    //writeMessageDHSE(handshakeState, message) 
    return SC_OK;
}



// Read operationss
sc_err_t readMessageE(NoiseHandshakeState handshakeState, char* message){
    //TODO Sanity checks missing here
    
    //s.remoteEphemeralPubKey, err = msg.ReadEPublic()
	//s.symmState.MixHash(s.remoteEphemeralPubKey[:])
    return SC_OK;
}

sc_err_t readMessageDHEE(NoiseHandshakeState handshakeState, char* message){
    //s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteEphemeralPubKey))
    return SC_OK;
}

sc_err_t readMessageS(NoiseHandshakeState handshakeState, char* message){
    //TODO Sanity checks missing here
    /* idBytes, err := msg.ReadEncryptedIdentity()
	var decryptedRawIdentity []byte
	decryptedRawIdentity, err = s.symmState.DecryptAndHash(decryptedRawIdentity, idBytes)

	smCrt, err := smolcert.ParseBuf(decryptedRawIdentity)
	identity := &Identity{*smCrt}
	if err := s.eventuallyVerifyIdentity(identity); err != nil {
		return fmt.Errorf("Failed to verify remote identity: %w", err)
	}

	s.remoteIdentity = identity
    */
   return SC_OK;
}

sc_err_t readMessageDHES(NoiseHandshakeState handshakeState, char* message){
    //s.symmState.MixKey(s.symmState.DH(s.ephemeralDHKey.Private, s.remoteIdentity.PublicKey()));
    return SC_OK;
}

sc_err_t readMessageE_DHEE_S_DHES(NoiseHandshakeState handshakeState,char* message){
    readMessageE(handshakeState, message);
    readMessageDHEE(handshakeState, message);
    readMessageS(handshakeState, message);
    readMessageDHES(handshakeState, message);
    return SC_OK;
}

