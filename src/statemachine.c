#include "statemachine.h"

#include <string.h>
#include <stdio.h>
#include "handshake.h"
#include "transport.h"
#include "smol-noice-internal.h"
#include "port.h"



void* runnerTask(void* arg);

sc_err_t sc_init(smolNoice_t* smolNoice)
    {
    sc_err_t sc_err;
    NoiseDHState* localEphemeralKeypair = NULL; 
    NoiseProtocolId krach = {0};
    int noiseErr = 0;
    char errBuf[32];

    krach.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    krach.dh_id = NOISE_DH_CURVE25519;
    krach.hash_id = NOISE_HASH_BLAKE2s;
    krach.pattern_id = NOISE_PATTERN_XX;
    krach.prefix_id = NOISE_PREFIX_KRACH;
     

    NOISE_ERROR_CHECK(noise_handshakestate_new_by_id(&(smolNoice->handshakeState),&krach,NOISE_ROLE_INITIATOR));

    //TODO: Seed system RNG 
    localEphemeralKeypair = smolNoice->handshakeState->dh_local_ephemeral;
    NOISE_ERROR_CHECK(noise_dhstate_generate_keypair(localEphemeralKeypair));
   
    
    startTask(&runnerTask,(void*)smolNoice);    

    return SC_OK;
}


void* runnerTask(void* arg){
    smolNoice_t *taskData = (smolNoice_t*) arg;
    bool run = true;
    sc_err_t sc_err;
    taskData->handShakeStep = INIT_NETWORK;
    NoiseHandshakeState *handshakeState = taskData->handshakeState;
    NoiseCipherState *rxCipher=NULL;

    sc_handshakeInitPacket      initPaket={0};
    sc_handshakeResponsePacket  responsePaket={0};
    sc_handshakeFinPacket       finPaket={0};

    sn_msg_t networkMsg = {0};
    printf("Starting main loop\n");
    while(run){
        sleep_ms(20);
        switch(taskData->handShakeStep){
            case INIT_NETWORK:
                printf("State: INIT NETWORK\n");
                if(openSocket(taskData) == 0){
                     taskData->handShakeStep = SEND_INIT;
                }else{
                    printf("error initialing socket\n");
                     taskData->handShakeStep = ERROR;
                }
            break;

            case SEND_INIT:
                printf("State: SEND INIT\n");
                
                STATE_ERROR_CHECK(writeMessageE(taskData,&initPaket));
                initPaket.HandshakeType = HANDSHAKE_INIT;
               
                STATE_ERROR_CHECK(packHandshakeInit(&initPaket,&networkMsg));
                sendOverNetwork(taskData,&networkMsg);
                 taskData->handShakeStep = WAIT_FOR_RES;
            break;    

            case WAIT_FOR_RES:
                printf("State: WAIT FOR RESPONSE\n");
                if(messageFromNetwork(taskData,&networkMsg)){
                    STATE_ERROR_CHECK(unpackHandshakeResponse(&responsePaket,&networkMsg));
                    STATE_ERROR_CHECK(readMessageE_DHEE_S_DHES(taskData, &responsePaket));

                     taskData->handShakeStep = SEND_FIN;
                     free(networkMsg.msgBuf);
                 }
            break;     

            case SEND_FIN:
                printf("State: SEND FINISH\n");

                STATE_ERROR_CHECK(writeMessageS_DHSE(taskData, &finPaket));
                STATE_ERROR_CHECK(splitCipher(taskData));

                finPaket.HandshakeType = HANDSHAKE_FIN;
                STATE_ERROR_CHECK(packHandshakeFin(&finPaket,&networkMsg));
                
                sendOverNetwork(taskData, &networkMsg);
                 taskData->handShakeStep = DO_TRANSPORT;
            break;            
             
            case DO_TRANSPORT:
                //printf("State: DO TRANSPORT\n");
                if(messageFromNetwork(taskData,&networkMsg)){
                    //STATE_ERROR_CHECK(unpackTransport(&rxPaket,&networkMsg));
                    //TransportPakets dont need to be unpacked, since its format is same as networkmessage
                    STATE_ERROR_CHECK(decryptTransport(taskData, &networkMsg));
                    if(taskData->transportCallback != NULL){
                        taskData->transportCallback(networkMsg.msgBuf,networkMsg.msgLen);
                    }
                    networkMsg.msgBuf -= 2;
                    free(networkMsg.msgBuf);
                 }


                pthread_mutex_lock(taskData->txQueueLock);
                if(messageInQueue(taskData->txQueue) == DATA_AVAILIBLE){
                    sn_msg_t* data = NULL;
                    getMessageFromQueue(taskData->txQueue,&data);
                    encryptAndSendTransport(taskData,(sn_buffer_t*) data);
                    free(data->msgBuf);
                    free(data);
                }
                pthread_mutex_unlock(taskData->txQueueLock);
            break;    

            case ERROR: 
                printf("Error in Handshake - abort\n");
                run = false;
            break;        

            default: 
                printf("Unknown state, you should never see this message - abort!\n");
                run = false;
            break;
    }
}
return NULL;
}
