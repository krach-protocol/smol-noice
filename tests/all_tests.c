#include "smolcert.h"
#include "unity.h"

#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include "handshake.h"
#include "sc_packet.h"
#include "sc_err.h"

#define CWD_BUF_SIZE 128
#define CERT_PATH "/tests/krach-test-helper/client.smolcert"

void test_makeNoiseHandshake(void);
void test_packHandshakeInit(void);
void test_unpackHandshakeResponse(void);
void test_packHandshakeFin(void);

sc_error_t loadSmolCert(const char*,smolcert_t**);

#define DUMMY_PUBKEY 0x66 ,0x82 ,0x79 ,0x97 ,0x37 ,0xB7 ,0x6C ,0x17 , \
                      0xC3 ,0x5B ,0x95 ,0x57 ,0x44 ,0x9A ,0x86 ,0x22 , \
                      0xA7 ,0xB8 ,0xA5 ,0x65 ,0x5C ,0xB3 ,0x85 ,0x1C , \
                      0x74 ,0x4A ,0xFD ,0x69 ,0xEC ,0x95 ,0x9E ,0x29 
#define DUMMY_PUBKEY_ARRAY {DUMMY_PUBKEY}

#define INIT_PACKET_VERSION 0x01
#define INIT_PACKET_TYPE HANDSHAKE_INIT
#define INIT_PACKET_LEN 0x22, 0x00

#define FIN_PACKET_VERSION 0x01
#define FIN_PACKET_TYPE HANDSHAKE_FIN
#define FIN_PACKET_LEN 0x00, 0x22

#define RESPONSE_PACKET_VERSION 0x01
#define RESPONSE_PACKET_TYPE HANDSHAKE_RESPONSE

void test_packHandshakeFin(void){
  uint8_t handshakeTestVektor[] = {INIT_PACKET_LEN,FIN_PACKET_VERSION,FIN_PACKET_TYPE,DUMMY_PUBKEY};
  smolcert_t *testCert;
  sc_err_t err;
  sn_msg_t testMsg;
  sc_handshakeFinPacket testPacket;
    
  //Test for correct test-vector padding
  TEST_ASSERT_EQUAL_MESSAGE(FIN_PACKET_VERSION,handshakeTestVektor[2],"Packetversion-index in testpacket wrong");
  TEST_ASSERT_EQUAL_MESSAGE(FIN_PACKET_TYPE,handshakeTestVektor[3],"Packettype-index in testpacket wrong");

  //And copy public key to test-vector
  //memcpy(&(handshakeTestVektor[4]),testCert->public_key,32);

  //Build testpacket
  testPacket.HandshakeType = FIN_PACKET_TYPE;
  //testPacket.ephemeralPubKey = (uint8_t*)malloc(32);
  //memcpy(testPacket.ephemeralPubKey,testCert->public_key,32); 

    //pack the packet
  err = packHandshakeFin(&testPacket,&testMsg);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);

  //aaaannnndd?
  TEST_ASSERT_EQUAL_MESSAGE(36,testMsg.msgLen,"Test packet length doesnt match");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(handshakeTestVektor, testMsg.msgBuf,36,"Failed to pack handshake message");


}

void test_unpackHandshakeResponse(void){
  sn_msg_t testMsg = {0};
  sc_handshakeResponsePacket testPacket = {0};
  sc_err_t err = Sc_No_Error;
  time_t t;

  srand((unsigned) time(&t));

  //Craft test message
  uint16_t messageLen = 34; //length of packetLen not included 
  uint16_t payloadLen = (16-messageLen%16); //Filling up the payload to divisible by 16 len, for testing
  uint16_t totalLen = messageLen + payloadLen; 
  const uint8_t dummyPubkey[] = { 0x66 ,0x82 ,0x79 ,0x97 ,0x37 ,0xB7 ,0x6C ,0x17 , \
                                  0xC3 ,0x5B ,0x95 ,0x57 ,0x44 ,0x9A ,0x86 ,0x22 , \
                                  0xA7 ,0xB8 ,0xA5 ,0x65 ,0x5C ,0xB3 ,0x85 ,0x1C , \
                                  0x74 ,0x4A ,0xFD ,0x69 ,0xEC ,0x95 ,0x9E ,0x29};

  testMsg.msgBuf = (uint8_t*)malloc((size_t)totalLen+2);
  testMsg.msgLen = totalLen+2;
  testMsg.msgBuf[0] = totalLen&0xFF;
  testMsg.msgBuf[1] = (totalLen&0xFF00 )>>8;
  testMsg.msgBuf[2] = RESPONSE_PACKET_VERSION;
  testMsg.msgBuf[3] = RESPONSE_PACKET_TYPE;
  memcpy((uint8_t*)&(testMsg.msgBuf[4]),dummyPubkey,32);

  for(uint8_t rIdx = 0; rIdx < payloadLen; rIdx++){
    testMsg.msgBuf[36+rIdx] = (uint8_t)rand();
  }

  err = unpackHandshakeResponse(&testPacket, &testMsg);
  TEST_ASSERT_EQUAL_MESSAGE(Sc_No_Error,err,"Failed to unpack message");

  TEST_ASSERT_EQUAL_MESSAGE(RESPONSE_PACKET_TYPE,testPacket.HandshakeType, "Failed to parse messagetype");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&dummyPubkey,testPacket.ephemeralPubKey,32,"Failed to parse ephemeral public key");

  TEST_ASSERT_EQUAL_MESSAGE(payloadLen,testPacket.encryptedPayloadLen,"Wrong payload length // Failed to parse payload length");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&(testMsg.msgBuf[36]),testPacket.encryptedPayload,payloadLen,"Failed to parse payload");
}


void test_packHandshakeInit(void){
  uint8_t handshakeTestVektor[] = {INIT_PACKET_LEN,INIT_PACKET_VERSION,INIT_PACKET_TYPE,DUMMY_PUBKEY};
  smolcert_t *testCert;
  sc_err_t err;
  sn_msg_t testMsg;
  sc_handshakeInitPacket testPacket;
  char certFilePath[CWD_BUF_SIZE];

  //Load test-client-cert
  testCert = (smolcert_t*)malloc(sizeof(smolcert_t));
  getcwd(certFilePath, CWD_BUF_SIZE);
  strcat(certFilePath,CERT_PATH);
  err =  loadSmolCert(certFilePath,&testCert);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);

  
  //Test for correct test-vector padding
  TEST_ASSERT_EQUAL_MESSAGE(INIT_PACKET_VERSION,handshakeTestVektor[2],"Packetversion-index in testpacket wrong");
  TEST_ASSERT_EQUAL_MESSAGE(INIT_PACKET_TYPE,handshakeTestVektor[3],"Packettype-index in testpacket wrong");

  //And copy public key to test-vector
  memcpy(&(handshakeTestVektor[4]),testCert->public_key,32);

  //Build testpacket
  testPacket.HandshakeType = INIT_PACKET_TYPE;
  testPacket.ephemeralPubKey = (uint8_t*)malloc(32);
  memcpy(testPacket.ephemeralPubKey,testCert->public_key,32); 

  //Test if ephemeral-publickey was properly copied
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testCert->public_key,testPacket.ephemeralPubKey,32,"Failed to copy public key");
  
  //pack the packet
  err = packHandshakeInit(&testPacket,&testMsg);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);

  //aaaannnndd?
  TEST_ASSERT_EQUAL_MESSAGE(36,testMsg.msgLen,"Test packet length doesnt match");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(handshakeTestVektor, testMsg.msgBuf,36,"Failed to pack handshake message");


}


void test_makeNoiseHandshake(void){
  smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
  const char* host = "127.0.0.1";
  sc_error_t err;
  char certFilePath[CWD_BUF_SIZE];
  getcwd(certFilePath, CWD_BUF_SIZE);
  printf("Current working directory: %s\n",certFilePath);
  strcat(certFilePath,CERT_PATH);
  printf("Full certpath: %s\n",certFilePath);
  
  err =  loadSmolCert(certFilePath,&clientCert);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);
  if(err == Sc_No_Error){
    sc_init(clientCert,host,9095);
  }else{
    printf("Error initialzing cert");
  }

  while(1);
    printf("End");
}

int main(void) {
    if (sodium_init() == -1) {
      return 1;
    }
    UNITY_BEGIN();
    
    RUN_TEST(test_packHandshakeInit);
    RUN_TEST(test_unpackHandshakeResponse);
    //RUN_TEST(test_packHandshakeFin);
    RUN_TEST(test_makeNoiseHandshake);

    return UNITY_END();
    
    return 0;
}



// Utility
sc_error_t loadSmolCert(const char* fileName,smolcert_t** cert){
  FILE *fp;
  uint8_t* buf;
  size_t bufSize;
  
  sc_error_t sc_err;
  fp = fopen(fileName,"rb");

  if(fp == NULL){
    printf("File not found");
    TEST_ABORT();
  }

  fseek(fp,0,SEEK_END);
  bufSize = ftell(fp);
  rewind(fp);

  buf = (uint8_t*)malloc(bufSize);
  fread(buf,1,bufSize,fp);
  sc_err = sc_parse_certificate(buf,bufSize, *cert);
  free(buf);
  return sc_err;
}
