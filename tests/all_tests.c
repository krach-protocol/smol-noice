#include "smolcert.h"
#include "unity.h"

#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#include "handshake.h"
#include "sc_packet.h"
#include "sc_err.h"

#define CWD_BUF_SIZE 128
#define CERT_PATH "/tests/krach-test-helper/client.smolcert"

void test_makeNoiseHandshake(void);
void test_packHandshakeInit(void);
void test_unpackHandshakeResponse(void);

sc_error_t loadSmolCert(const char*,smolcert_t**);

#define DUMMY_PUBKEY  0x66 ,0x82 ,0x79 ,0x97 ,0x37 ,0xB7 ,0x6C ,0x17 , \
                      0xC3 ,0x5B ,0x95 ,0x57 ,0x44 ,0x9A ,0x86 ,0x22 , \
                      0xA7 ,0xB8 ,0xA5 ,0x65 ,0x5C ,0xB3 ,0x85 ,0x1C , \
                      0x74 ,0x4A ,0xFD ,0x69 ,0xEC ,0x95 ,0x9E ,0x29 
        
#define INIT_PACKET_VERSION 0x01
#define INIT_PACKET_TYPE HANDSHAKE_INIT
#define INIT_PACKET_LEN 0x00, 0x22



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
  TEST_ASSERT_EQUAL_MESSAGE(PACKET_VERSION,handshakeTestVektor[2],"Packetversion-index in testpacket wrong");
  TEST_ASSERT_EQUAL_MESSAGE(PACKET_TYPE,handshakeTestVektor[3],"Packettype-index in testpacket wrong");

  //And copy public key to test-vector
  memcpy(&(handshakeTestVektor[4]),testCert->public_key,32);

  //Build testpacket
  testPacket.HandshakeType = PACKET_TYPE;
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
}

int main(void) {
    if (sodium_init() == -1) {
      return 1;
    }
    UNITY_BEGIN();
    
    RUN_TEST(test_packHandshakeInit);
    //RUN_TEST(test_makeNoiseHandshake);

    return UNITY_END();
    //while(1);
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
