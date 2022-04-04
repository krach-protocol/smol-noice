#include "handshake.h"
#include "transport.h"

#include <sodium.h>


#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <noise/protocol.h>

#include "smolcert.h"

#include "smol-noice-internal.h"

#define PUBKEY_LEN 32

/**
 * Since we know this implementation is fully based on the krach-protocol and is only used as
 * a client-implementation we can skip a lot of checks from the echo-tutorial (http://rweather.github.io/noise-c/example_echo.html)
 * f
 *  Nice function for all sanity checks: noise_handshakestate_get_action 
 *  http://rweather.github.io/noise-c/group__symmetricstate.html
 * 
 * 
 * 
*/

sc_err_t sn_init(smolNoice_t* smolNoice) {

    NoiseDHState* localEphemeralKeypair = NULL; 
    NoiseProtocolId krach = {0};

    krach.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach.dh_id = NOISE_DH_CURVE25519;
    krach.hash_id = NOISE_HASH_BLAKE2s;
    krach.pattern_id = NOISE_PATTERN_XX;
    krach.prefix_id = NOISE_PREFIX_KRACH;

    NOISE_ERROR_CHECK(noise_handshakestate_new_by_id(&(smolNoice->handshakeState),&krach,NOISE_ROLE_INITIATOR));

    //TODO: Seed system RNG 
    localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral;
    NOISE_ERROR_CHECK(noise_dhstate_generate_keypair(localEphemeralKeypair));   

    return SC_OK;
}

sc_err_t run_handshake(smolNoice_t* smol_noice) {
    sn_handshake_init_packet init_pkt;
    sn_buffer_t* buf = sn_buffer_new(512);
    sc_err_t err = SC_OK;
    if((err = writeMessageE(smol_noice, &init_pkt)) != SC_OK ){
        sn_buffer_free(buf);
        return err;
    }
    if((err = pack_handshake_init(&init_pkt, buf)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    
    if((err = sn_send_buffer(smol_noice->socket, buf)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    sn_buffer_reset(buf);

    if(( err = sn_read_from_socket(smol_noice->socket, buf, 3)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    } // We are expecting to read 3 bytes, type and length
    if(buf->idx[0] != HANDSHAKE_RESPONSE) {
        sn_buffer_free(buf);
        return Sc_Validation_Error;
    }
    
    buf->idx++;
    buf->len--;
    uint16_t pkt_len = 0;
    err = sn_buffer_read_uint16(buf, &pkt_len);
    if(err != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    
    if(( err = sn_read_from_socket(smol_noice->socket, buf, pkt_len)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    sn_buffer_rewind(buf);
    
    sn_handshake_response_packet rsp_pkt = {0};
    if(( err = unpack_handshake_response(&rsp_pkt, buf)) != SC_OK) {
        sn_buffer_free(buf);
        sn_buffer_free(rsp_pkt.smolcert);
        sn_buffer_free(rsp_pkt.payload);
        return err;
    }
    
    sn_buffer_reset(buf);
    if(( err = readMessageE_DHEE_S_DHES(smol_noice, &rsp_pkt)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    sn_buffer_free(rsp_pkt.smolcert);
    sn_buffer_free(rsp_pkt.payload);
    
    sn_handshake_fin_packet fin_pkt = {0};
    if(( err = writeMessageS_DHSE(smol_noice, &fin_pkt)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    if((err = pack_handshake_fin(&fin_pkt, buf)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    if((err = sn_send_buffer(smol_noice->socket, buf)) != SC_OK) {
        sn_buffer_free(buf);
        sn_buffer_free(fin_pkt.encrypted_identity);
        sn_buffer_free(fin_pkt.encrypted_payload);
        return err;
    }
    
    sn_buffer_free(fin_pkt.encrypted_identity);
    sn_buffer_free(fin_pkt.encrypted_payload);
    if((err = sn_split_cipher(smol_noice)) != SC_OK) {
        sn_buffer_free(buf);
        return err;
    }
    sn_buffer_free(buf);
    return err;
}

sc_err_t writeMessageE(smolNoice_t* smolNoice, sn_handshake_init_packet* packet){
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseDHState *dhState;   
    uint8_t pubKey[PUBKEY_LEN];

    dhState = smolNoice->handshakeState->dh_local_ephemeral;
    
    NOISE_ERROR_CHECK(noise_dhstate_get_public_key(dhState,pubKey,PUBKEY_LEN));
    
    packet->ephemeralPubKey = (uint8_t*)calloc(PUBKEY_LEN,sizeof(uint8_t));
    memcpy(packet->ephemeralPubKey,pubKey,PUBKEY_LEN);

    NOISE_ERROR_CHECK(noise_symmetricstate_mix_hash(symmState,pubKey,PUBKEY_LEN));

   	return SC_OK;
}

sc_err_t writeMessageS(smolNoice_t* smolNoice, sn_handshake_fin_packet* packet){
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseBuffer buff;
    noise_buffer_init(buff);
    sn_buffer_t* cert_buffer = sn_buffer_new(256);
    cert_buffer->idx += 1; // Give the buffer more chance for more efficient padding
    sn_buffer_ensure_cap(cert_buffer, smolNoice->clientCertLen + 33); // Ensure we have enough memory for padding + MAC
    sn_buffer_write_into(cert_buffer, smolNoice->clientCert, smolNoice->clientCertLen);
    SC_ERROR_CHECK(sn_buffer_pad(cert_buffer));
    sn_buffer_ensure_cap(cert_buffer, cert_buffer->len + 16); // Ensure we have enough memory reserved for the MAC
    
    noise_buffer_set_inout(buff, cert_buffer->idx, cert_buffer->len, cert_buffer->_cap);
    NOISE_ERROR_CHECK(noise_symmetricstate_encrypt_and_hash(symmState ,&buff));
    cert_buffer->len += 16; // Signal the there is now a MAC at the end of the buffer
   
    packet->encrypted_identity = cert_buffer;
    packet->HandshakeType = HANDSHAKE_FIN;

    // TODO, do the same with payload, if payload is set
    
    return SC_OK;
}

sc_err_t writeMessageDHSE(smolNoice_t* smolNoice, sn_handshake_fin_packet* packet){
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseDHState *localStaticKeyPair = smolNoice->handshakeState->dh_local_static;
    NoiseDHState *remoteEphemeralKeyPair = smolNoice->handshakeState->dh_remote_ephemeral;
    uint8_t DHresult[32];
    uint8_t localPrivateStaticBufferCURVE25519[32];
    size_t DHresultSize = 32;



    if(crypto_sign_ed25519_sk_to_curve25519(localPrivateStaticBufferCURVE25519,smolNoice->clientPrivateKey) != 0){
        return SC_ERR;
    }

    NOISE_ERROR_CHECK(noise_dhstate_set_keypair_private(localStaticKeyPair,localPrivateStaticBufferCURVE25519,32) );


    NOISE_ERROR_CHECK(noise_dhstate_calculate(localStaticKeyPair,remoteEphemeralKeyPair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));


    return SC_OK;
}

sc_err_t writeMessageS_DHSE(smolNoice_t* smolNoice, sn_handshake_fin_packet* packet){
    SC_ERROR_CHECK(writeMessageS(smolNoice, packet));
    SC_ERROR_CHECK(writeMessageDHSE(smolNoice, packet));
    
    return SC_OK;
}



// Read operations
sc_err_t readMessageE(smolNoice_t* smolNoice, sn_handshake_response_packet *packet){    
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseDHState *remoteEphemeralKeypair = smolNoice->handshakeState->dh_remote_ephemeral;


    NOISE_ERROR_CHECK(noise_dhstate_set_public_key(remoteEphemeralKeypair, packet->ephemeralPubKey, 32));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_hash(symmState,packet->ephemeralPubKey,32));
    
    free(packet->ephemeralPubKey);

    return SC_OK;
}

sc_err_t readMessageDHEE(smolNoice_t* smolNoice, sn_handshake_response_packet *packet){
    NoiseDHState *localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral;
    NoiseDHState *remoteEphemeralKeypair = smolNoice->handshakeState->dh_remote_ephemeral;
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;

    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteEphemeralKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}

sc_err_t readMessageS(smolNoice_t* smolNoice, sn_handshake_response_packet *packet){
    NoiseDHState* remoteStaticKeypair = NULL;
    uint8_t remote_pub_key[32];
    smolcert_t remote_cert = {0};

    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    NoiseBuffer idBuffer;
    
    noise_buffer_init(idBuffer);
    noise_buffer_set_input(idBuffer, packet->smolcert->idx,packet->smolcert->len);
   
    NOISE_ERROR_CHECK(noise_symmetricstate_decrypt_and_hash(symmState,&idBuffer));
    packet->smolcert->len -= 16; // Remove the MAC from the length of the buffer;
   
    SC_ERROR_CHECK(sn_buffer_unpad(packet->smolcert));
   

    if( sc_parse_certificate(packet->smolcert->idx,packet->smolcert->len, &remote_cert) != Sc_No_Error){
        return SC_ERR;
    }
    
    SC_ERROR_CHECK(smolNoice->certCallback(packet->smolcert->idx,packet->smolcert->len,&remote_cert));
    
    //TODO check why validation fails
    //if(sc_validate_certificate_signature(packet->smolcert, packet->smolcertLen, rootPubKey) != SC_OK) return SC_ERR;
    

    if( sc_get_curve_public_key(&remote_cert, remote_pub_key) != Sc_No_Error) {
        return SC_ERR;
    }
    
    //Finally set the remote public Key in handshake state
    remoteStaticKeypair = noise_handshakestate_get_remote_public_key_dh(smolNoice->handshakeState);
    if(remoteStaticKeypair == NULL) return SC_ERR;
    NOISE_ERROR_CHECK(noise_dhstate_set_public_key(remoteStaticKeypair, remote_pub_key, 32))

    
   return SC_OK;
}

sc_err_t readMessageDHES(smolNoice_t* smolNoice, sn_handshake_response_packet *packet){
    NoiseDHState *remoteStaticKeypair = smolNoice->handshakeState->dh_remote_static; 
    NoiseDHState *localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral; 
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;
    uint8_t DHresult[32];
    size_t DHresultSize = 32;

    NOISE_ERROR_CHECK(noise_dhstate_calculate(localEphemeralKeypair,remoteStaticKeypair,DHresult,DHresultSize));
    NOISE_ERROR_CHECK(noise_symmetricstate_mix_key(symmState,DHresult,DHresultSize));

    return SC_OK;
}
sc_err_t readMessageE_DHEE_S_DHES(smolNoice_t* smolNoice, sn_handshake_response_packet* packet){
    
    SC_ERROR_CHECK(readMessageE(smolNoice, packet));
    SC_ERROR_CHECK(readMessageDHEE(smolNoice, packet));
    SC_ERROR_CHECK(readMessageS(smolNoice, packet));
    SC_ERROR_CHECK(readMessageDHES(smolNoice, packet));
    return SC_OK;
}

/*
sc_err_t printNoiseErr(int noiseErr){
    char errBuf[32];

    if(noiseErr != NOISE_ERROR_NONE){
        noise_strerror(noiseErr, errBuf, 32);
        printf("Noise Error: %s \n",errBuf);
        return SC_ERR;
    }

    return SC_OK;
}
*/


/*
void printCryptoData(NoiseHandshakeState *handshakeState){
    NoiseCipherState* cipher = handshakeState->symmetric->cipher;
    NoiseHashState* hash = handshakeState->symmetric->hash;
}
*/

/*
sc_err_t unpadBuffer(sn_buffer_t* buffer){
    uint8_t bufferLen = buffer->msgLen;
    uint8_t paddedBytes = buffer->msgBuf[0];
     for(uint8_t idx = 0;idx<bufferLen-(16+paddedBytes);idx++){
        buffer->msgBuf[idx] = buffer->msgBuf[idx+1];
    }
    buffer->msgBuf[bufferLen-(16+paddedBytes)] = '\0';


    return SC_OK;
}
*/
sc_err_t sn_split_cipher(smolNoice_t* smolNoice){
     //split symmetric state for encrypt(first cipher) and decrypt(second cipher)
    //see: http://rweather.github.io/noise-c/group__symmetricstate.html#gadf7cef60a64aef703add9b093c3b6c63
    NoiseSymmetricState *symmState = smolNoice->handshakeState->symmetric;

    NOISE_ERROR_CHECK(noise_symmetricstate_split(symmState,&(smolNoice->txCipher),&(smolNoice->rxCipher)));


    NOISE_ERROR_CHECK(noise_handshakestate_free(smolNoice->handshakeState));
    return SC_OK;
}
