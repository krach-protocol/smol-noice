#include "transport.h"
#include "sc_err.h"
#include <stdio.h>


sc_err_t encryptTransport(NoiseCipherState* txCipher,sn_buffer_t* paket){
    NoiseBuffer txBuffer;

    SC_ERROR_CHECK(padBuffer(paket));
    noise_buffer_set_inout(txBuffer, paket->msgBuf, paket->msgLen-16, paket->msgLen);
    NOISE_ERROR_CHECK(noise_cipherstate_encrypt(txCipher,&txBuffer));	
    return SC_OK;
}
sc_err_t decryptTransport(NoiseCipherState* rxCipher,sn_buffer_t* paket){
    NoiseBuffer rxBuffer;
    SC_ERROR_CHECK(unpadBuffer(paket));
    noise_buffer_set_inout(rxBuffer,paket->msgBuf,paket->msgLen,paket->msgLen);
    NOISE_ERROR_CHECK(noise_cipherstate_decrypt(rxCipher,&rxBuffer));

    return SC_OK;
}
