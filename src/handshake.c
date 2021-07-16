#include "handshake.h"
#include "transport.h"

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <noise/protocol.h>

#include "smolcert.h"
#include "port.h"

#include "smol-noice-internal.h"



void printHex(uint8_t*,uint8_t);


//Error Utils




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

sc_err_t writeMessageE(smolNoice_t* smolNoice,sc_handshakeInitPacket* packet){
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseDHState *dhState;   
    size_t pubKeyLen;
    uint8_t* pubKey;
    int noiseErr = 0;
    char errBuf[32];

    dhState = smolNoice->handshakeState->dh_local_ephemeral;
    pubKeyLen = noise_dhstate_get_public_key_length(dhState);
    pubKey = (uint8_t*)malloc(pubKeyLen);
    
    NOISE_ERROR_CHECK(noise_dhstate_get_public_key(dhState,pubKey,pubKeyLen));
    
    packet->ephemeralPubKey = (uint8_t*)malloc(pubKeyLen);
    memcpy(packet->ephemeralPubKey,pubKey,pubKeyLen);

    NOISE_ERROR_CHECK(noise_symmetricstate_mix_hash(symmState,pubKey,pubKeyLen));

    free(pubKey);
   	return SC_OK;
}

sc_err_t writeMessageS(smolNoice_t* smolNoice, sc_handshakeFinPacket* packet){
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseBuffer buff;
    noise_buffer_init(buff);
    int noiseErr = 0;
    char errBuf[32];
    sn_buffer_t certBuffer;

    certBuffer.msgLen = smolNoice->clientCertLen;
    certBuffer.msgBuf = (uint8_t*)malloc(certBuffer.msgLen);
    memcpy(certBuffer.msgBuf,smolNoice->clientCert,certBuffer.msgLen);

    SC_ERROR_CHECK(padBuffer(&certBuffer));
    
    noise_buffer_set_inout(buff,certBuffer.msgBuf,certBuffer.msgLen-16,certBuffer.msgLen);
    
    NOISE_ERROR_CHECK(noise_symmetricstate_encrypt_and_hash(symmState,&buff));

    packet->encryptedIdentityLen = certBuffer.msgLen;
    packet->encryptedIdentity = (uint8_t*)malloc(packet->encryptedIdentityLen);
    memcpy(packet->encryptedIdentity,certBuffer.msgBuf,packet->encryptedIdentityLen);

    free(certBuffer.msgBuf);
    packet->HandshakeType = HANDSHAKE_FIN;
    
    return SC_OK;
}

sc_err_t writeMessageDHSE(smolNoice_t* smolNoice, sc_handshakeFinPacket* packet){
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseDHState *remoteStaticKeypair, *localEphemeralKeypair;
    NoiseCipherState *sendCipher, *receiveCipher;
    uint8_t DHresult[32];
    size_t DHresultSize = 32;



    remoteStaticKeypair = noise_handshakestate_get_remote_public_key_dh(smolNoice->handshakeState); 
    localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral;
   
    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteStaticKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}

sc_err_t writeMessageS_DHSE(smolNoice_t* smolNoice, sc_handshakeFinPacket* packet){
    SC_ERROR_CHECK(writeMessageS(smolNoice, packet));
    SC_ERROR_CHECK(writeMessageDHSE(smolNoice, packet));
    
    return SC_OK;
}



// Read operations
sc_err_t readMessageE(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet){    
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseDHState *remoteEphemeralKeypair = smolNoice->handshakeState->dh_remote_ephemeral;


    NOISE_ERROR_CHECK(noise_dhstate_set_public_key(remoteEphemeralKeypair, packet->ephemeralPubKey, 32));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_hash(symmState,packet->ephemeralPubKey,32));
    
    return SC_OK;
}

sc_err_t readMessageDHEE(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet){
    NoiseDHState *localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral;
    NoiseDHState *remoteEphemeralKeypair = smolNoice->handshakeState->dh_remote_ephemeral;
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;

    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteEphemeralKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}

sc_err_t readMessageS(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet){
     NoiseDHState* remoteStaticKeypair = NULL;
     uint8_t remotePubKey[32];
     smolcert_t remoteCert = {0};

    uint8_t* DHresult = NULL;
    size_t DHresultSize = 0;
    int noiseErr = 0;
    char errBuf[32];

   NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
   NoiseBuffer idBuffer;
    sn_buffer_t smolCertBuffer;
    
   
   noise_buffer_init(idBuffer);
   noise_buffer_set_input(idBuffer, packet->smolcert,packet->smolcertLen);
   
   NOISE_ERROR_CHECK(noise_symmetricstate_decrypt_and_hash(symmState,&idBuffer));
   

    smolCertBuffer.msgBuf=packet->smolcert;
    smolCertBuffer.msgLen=packet->smolcertLen;
    SC_ERROR_CHECK(unpadBuffer(&smolCertBuffer));
    packet->smolcertLen = smolCertBuffer.msgLen;
   

    if( sc_parse_certificate(packet->smolcert,packet->smolcertLen, &remoteCert) != Sc_No_Error){
        return SC_ERR;
    }
    
    //TODO implement callback for cert handling
    
    //TODO check why validation fails
    //if(sc_validate_certificate_signature(packet->smolcert, packet->smolcertLen, rootPubKey) != SC_OK) return SC_ERR;
    

    if( sc_get_curve_public_key(&remoteCert,remotePubKey) != Sc_No_Error) {
        return SC_ERR;
    }
    
    //Finally set the remote public Key in handshake state
    remoteStaticKeypair = noise_handshakestate_get_remote_public_key_dh(smolNoice->handshakeState);
    if(remoteStaticKeypair == NULL) return SC_ERR;
    NOISE_ERROR_CHECK(noise_dhstate_set_public_key(remoteStaticKeypair,remotePubKey,32))

    
   return SC_OK;
}

sc_err_t readMessageDHES(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet){
    NoiseDHState *remoteStaticKeypair = smolNoice->handshakeState->dh_remote_static; 
    NoiseDHState *localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral; 
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteStaticKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}
sc_err_t readMessageE_DHEE_S_DHES(smolNoice_t* smolNoice, sc_handshakeResponsePacket *packet){
    
    SC_ERROR_CHECK(readMessageE(smolNoice, packet));
    SC_ERROR_CHECK(readMessageDHEE(smolNoice, packet));
    SC_ERROR_CHECK(readMessageS(smolNoice, packet));
    SC_ERROR_CHECK(readMessageDHES(smolNoice, packet));
    return SC_OK;
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



void printCryptoData(NoiseHandshakeState *handshakeState){
    NoiseCipherState* cipher = handshakeState->symmetric->cipher;
    NoiseHashState* hash = handshakeState->symmetric->hash;
}

sc_err_t sendTransport(sn_buffer_t txData);
sc_err_t sendTransport(sn_buffer_t txData){


}
sc_err_t unpadBuffer(sn_buffer_t* buffer){
    uint8_t bufferLen = buffer->msgLen;
    uint8_t paddedBytes = buffer->msgBuf[0];
     for(uint8_t idx = 0;idx<bufferLen-(16+paddedBytes);idx++){
        buffer->msgBuf[idx] = buffer->msgBuf[idx+1];
    }
    buffer->msgBuf[bufferLen-(16+paddedBytes)] = '\0';


    return SC_OK;
}
sc_err_t splitCipher(smolNoice_t* smolNoice){
     //split symmetric state for encrypt(first cipher) and decrypt(second cipher)
    //see: http://rweather.github.io/noise-c/group__symmetricstate.html#gadf7cef60a64aef703add9b093c3b6c63
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NOISE_ERROR_CHECK(noise_symmetricstate_split(symmState,&(smolNoice->rxCipher),&(smolNoice->txCipher)));

    NOISE_ERROR_CHECK(noise_handshakestate_free(smolNoice->handshakeState));
    //NOTE: possibly noise-c handles this for itself
    return SC_OK;
}
