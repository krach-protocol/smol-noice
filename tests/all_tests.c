#include "smolcert.h"
#include "unity.h"

#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include "handshake.h"
#include "sn_packet.h"
#include "sn_err.h"


#define CWD_BUF_SIZE 128
#define CERT_PATH "/tests/krach-test-helper/client.smolcert"
#define KEY_PATH "/tests/krach-test-helper/client.key"

void test_packHandshakeInit(void);
void test_unpackHandshakeResponse(void);
void test_packHandshakeFin(void);
void test_readWriteUint16(void);
void test_readLVBlock(void);
void test_writeLVBlock(void);
void test_NoiseName(void);
void test_smolNoice(void);
void test_bufferPadding(void);
void sleep_ms(uint16_t);


sn_err_t testTransportCallBack(uint8_t*, uint8_t);


sc_error_t loadSmolCert(const char*, smolcert_t*, sn_buffer_t*);
sn_err_t loadPrivateKey(const char*,uint8_t*);

#define DUMMY_PUBKEY 0x66 ,0x82 ,0x79 ,0x97 ,0x37 ,0xB7 ,0x6C ,0x17 , \
                      0xC3 ,0x5B ,0x95 ,0x57 ,0x44 ,0x9A ,0x86 ,0x22 , \
                      0xA7 ,0xB8 ,0xA5 ,0x65 ,0x5C ,0xB3 ,0x85 ,0x1C , \
                      0x74 ,0x4A ,0xFD ,0x69 ,0xEC ,0x95 ,0x9E ,0x29 
#define DUMMY_PUBKEY_ARRAY {DUMMY_PUBKEY}

#define INIT_PACKET_VERSION 0x01
#define INIT_PACKET_TYPE HANDSHAKE_INIT
#define INIT_PACKET_LEN 0x20, 0x00

#define FIN_PACKET_VERSION 0x01
#define FIN_PACKET_TYPE HANDSHAKE_FIN
#define FIN_PACKET_LEN 0x00, 0x22

#define RESPONSE_PACKET_VERSION 0x01
#define RESPONSE_PACKET_TYPE HANDSHAKE_RESPONSE

void test_NoiseName(void) {
  NoiseProtocolId *krach = (NoiseProtocolId*)calloc(1,sizeof(NoiseProtocolId));

  krach->cipher_id = NOISE_CIPHER_CHACHAPOLY;
  krach->dh_id = NOISE_DH_CURVE25519;
  krach->hash_id = NOISE_HASH_BLAKE2s;
  krach->pattern_id = NOISE_PATTERN_XX;
  krach->prefix_id = NOISE_PREFIX_KRACH;

  char name[NOISE_MAX_PROTOCOL_NAME];

  int err = noise_protocol_id_to_name(name, sizeof(name), krach);
  TEST_ASSERT_EQUAL_MESSAGE(NOISE_ERROR_NONE, err, "Formatting of noise protocol name failed");
  TEST_ASSERT_EQUAL_STRING_MESSAGE("Krach_XX_25519_ChaChaPoly_BLAKE2s", name, "krach protocol name does not match");
  free(krach);
}

void test_bufferPadding(void) {
  uint8_t testData[] = {0x01,0x02,0x03};

  sn_buffer_t* buf = sn_buffer_new(512);
  sn_buffer_write(buf, testData, 3);
  sn_buffer_rewind(buf);
  sn_buffer_pad(buf);

  TEST_ASSERT_EQUAL_INT_MESSAGE(16, buf->len, "Wrong length of padded buffer");
  TEST_ASSERT_EQUAL_INT8_MESSAGE(12, buf->idx[0], "Wrong padding header");
  TEST_ASSERT_EQUAL_INT8_MESSAGE(0x01, buf->idx[1], "Wrong first byte of payload");
  TEST_ASSERT_EQUAL_INT8_MESSAGE(0, buf->idx[5], "Padded bytes are not null");
  sn_buffer_free(buf);

  buf = sn_buffer_new(512);
  // Reserve space in front
  buf->idx += 1;
  sn_buffer_write(buf, testData, 3);
  buf->idx = buf->_orig_ptr+1;
  buf->len = 3;
  sn_buffer_pad(buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(16, buf->len, "Wrong length of padded buffer");
  TEST_ASSERT_EQUAL_INT8_MESSAGE(12, buf->idx[0], "Wrong padding header");
  TEST_ASSERT_EQUAL_INT8_MESSAGE(0x01, buf->idx[1], "Wrong first byte of payload");
  TEST_ASSERT_EQUAL_INT8_MESSAGE(0, buf->idx[5], "Padded bytes are not null");
  sn_buffer_free(buf);
}

void test_readWriteUint16(void) {
  uint8_t testInt[] = {0xE9,0x07};
  sn_buffer_t* buf = sn_buffer_new(32);
  sn_buffer_write_into(buf, testInt, 2);
  sn_buffer_rewind(buf);
  uint16_t i = 0;
  sn_buffer_read_uint16(buf, &i);
  TEST_ASSERT_EQUAL_MESSAGE(2025, i, "Failed to read little endian integer from byte array");

  sn_buffer_reset(buf);
  sn_buffer_write_uint16(buf, 2025);
  sn_buffer_rewind(buf);
  TEST_ASSERT_EQUAL_MESSAGE(0xE9, buf->idx[0], "Lower byte of uint16 does not match");
  TEST_ASSERT_EQUAL_MESSAGE(0x07, buf->idx[1], "Upper byte of uint16 does not match");
  sn_buffer_free(buf);
}

void test_readLVBlock(void) {
  uint8_t lvBlock[] = {0x08,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
  sn_buffer_t* buf = sn_buffer_new(64);
  sn_buffer_write_into(buf, lvBlock, 10);
  sn_buffer_rewind(buf);
  uint8_t* payload;
  uint16_t payloadLen = sn_buffer_peek_lv_len(buf);
  payload = (uint8_t*)malloc(payloadLen);
  sn_buffer_read_lv_block(buf, payload, payloadLen);
  sn_buffer_free(buf);
  TEST_ASSERT_EQUAL_MESSAGE(8, payloadLen, "Failed to read correct payload length");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE((uint8_t*)&lvBlock[2], payload, 8, "Failed to read correct payload from lv block");
}

void test_writeLVBlock(void) {
  uint8_t dataBlock[] = {0x01,0x02,0x03};
  sn_buffer_t* buf = sn_buffer_new(64);

  sn_buffer_write_lv_block(buf, dataBlock, 3);
  sn_buffer_rewind(buf);
  uint16_t readLength = sn_buffer_peek_lv_len(buf);
  TEST_ASSERT_EQUAL_MESSAGE(3, readLength, "Found invalid length at beginning of LV Block");
  TEST_ASSERT_EQUAL_MESSAGE(0x01, buf->idx[2], "Invalid data in LV Block");
  TEST_ASSERT_EQUAL_MESSAGE(0x02, buf->idx[3], "Invalid data in LV Block");
  TEST_ASSERT_EQUAL_MESSAGE(0x03, buf->idx[4], "Invalid data in LV Block");
  sn_buffer_free(buf);
}

void test_unpackHandshakeResponse(void){
  sn_buffer_t* buf = sn_buffer_new(256);
  sn_handshake_response_packet testPacket = {0};
  sn_err_t err = Sc_No_Error;
  time_t t;

  srand((unsigned) time(&t));

  //Craft test message
  uint16_t smolcertLen = 32; //Filling up the payload to divisible by 16 len, for testing
  uint16_t totalLen = 32 + 2 + smolcertLen; 
  const uint8_t dummyPubkey[] = { 0x66 ,0x82 ,0x79 ,0x97 ,0x37 ,0xB7 ,0x6C ,0x17 , \
                                  0xC3 ,0x5B ,0x95 ,0x57 ,0x44 ,0x9A ,0x86 ,0x22 , \
                                  0xA7 ,0xB8 ,0xA5 ,0x65 ,0x5C ,0xB3 ,0x85 ,0x1C , \
                                  0x74 ,0x4A ,0xFD ,0x69 ,0xEC ,0x95 ,0x9E ,0x29};

  buf->idx[0] = RESPONSE_PACKET_TYPE;
  buf->idx += 1;
  sn_buffer_write_uint16(buf, totalLen);
  sn_buffer_write(buf, (uint8_t*)&dummyPubkey, 32);
  uint8_t* mock_cert = (uint8_t*)malloc(smolcertLen);
  for(uint8_t rIdx = 0; rIdx < smolcertLen; rIdx++){
    mock_cert[rIdx] = (uint8_t)rand();
  }
  sn_buffer_write_lv_block(buf, mock_cert, smolcertLen);
  sn_buffer_rewind(buf);

  err = unpack_handshake_response(&testPacket, buf);
  sn_buffer_rewind(buf);
  TEST_ASSERT_EQUAL_MESSAGE(Sc_No_Error,err,"Failed to unpack message");

  TEST_ASSERT_EQUAL_MESSAGE(RESPONSE_PACKET_TYPE,testPacket.HandshakeType, "Failed to parse messagetype");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(&dummyPubkey,testPacket.ephemeralPubKey,32,"Failed to parse ephemeral public key");

  TEST_ASSERT_EQUAL_MESSAGE(smolcertLen,testPacket.smolcert->len,"Wrong smolcert length // Failed to parse smolcert length");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testPacket.smolcert->idx, &(buf->idx[37]),smolcertLen,"Failed to parse smolcert");

  free(testPacket.ephemeralPubKey);
  sn_buffer_free(buf);
}


void test_packHandshakeInit(void){
  uint8_t handshakeTestVektor[] = {INIT_PACKET_VERSION, INIT_PACKET_TYPE, INIT_PACKET_LEN,DUMMY_PUBKEY};
  smolcert_t *testCert;
  sn_err_t err;
  sn_buffer_t* certBuffer = sn_buffer_new(256);
  sn_handshake_init_packet testPacket;
  char certFilePath[CWD_BUF_SIZE];

  //Load test-client-cert
  testCert = (smolcert_t*)malloc(sizeof(smolcert_t));
  getcwd(certFilePath, CWD_BUF_SIZE);
  strcat(certFilePath,CERT_PATH);
  err =  loadSmolCert(certFilePath, testCert, certBuffer);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);

  
  //Test for correct test-vector padding
  TEST_ASSERT_EQUAL_MESSAGE(INIT_PACKET_VERSION,handshakeTestVektor[0],"Packetversion-index in testpacket wrong");
  TEST_ASSERT_EQUAL_MESSAGE(INIT_PACKET_TYPE,handshakeTestVektor[1],"Packettype-index in testpacket wrong");

  //And copy public key to test-vector
  memcpy(&(handshakeTestVektor[4]),testCert->public_key,32);

  //Build testpacket
  testPacket.HandshakeType = INIT_PACKET_TYPE;
  testPacket.ephemeralPubKey = (uint8_t*)calloc(32,sizeof(uint8_t));
  memcpy(testPacket.ephemeralPubKey,testCert->public_key,32); 

  //Test if ephemeral-publickey was properly copied
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testCert->public_key,testPacket.ephemeralPubKey,32,"Failed to copy public key");
  
  //pack the packet
  sn_buffer_t* buf = sn_buffer_new(1024);
  err = pack_handshake_init(&testPacket,buf);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);

  //aaaannnndd?
  TEST_ASSERT_EQUAL_MESSAGE(36,buf->len,"Test packet length doesnt match");
  TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(handshakeTestVektor, buf->idx, 36, "Failed to pack handshake message");

  free(testPacket.ephemeralPubKey);
  sn_buffer_free(buf);
  sn_buffer_free(certBuffer);
  free(testCert);
}

void test_packHandshakeFin(void) {
  sn_handshake_fin_packet pkt;
  pkt.encrypted_identity = sn_buffer_new(64);
  pkt.encrypted_payload = sn_buffer_new(64);
  pkt.HandshakeType = HANDSHAKE_FIN;
  uint8_t encryptedPayload[2] = { 0x01, 0x02 };
  pkt.encrypted_payload = sn_buffer_new(1024);
  sn_buffer_write_into(pkt.encrypted_payload, encryptedPayload, 2);

  sn_buffer_t* buf = sn_buffer_new(1024);
  sn_err_t err = pack_handshake_fin(&pkt, buf);
  TEST_ASSERT_EQUAL_MESSAGE(SN_OK, err, "Packing handshake fin packet failed");
  sn_buffer_free(buf);
  //TODO: compare against crafted paket
}

/*void test_makeNoiseHandshake(void){
  smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
  const char* host = "127.0.0.1";
  sc_error_t err;
  char certFilePath[CWD_BUF_SIZE];
  getcwd(certFilePath, CWD_BUF_SIZE);
  printf("Current working directory: %s\n",certFilePath);
  strcat(certFilePath,CERT_PATH);
  printf("Full certpath: %s\n",certFilePath);
  
  sn_buffer_t clientCertBuffer;
  sn_buffer_t rootCertBuffer;
  err =  loadSmolCert(certFilePath,&clientCert,&clientCertBuffer);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);
  if(err != Sc_No_Error){
    //sn_init(&clientCertBuffer,&rootCertBuffer,NULL,NULL,host,9095);
  }else{
    printf("Error initialzing cert");
  }

  while(1);
    printf("End");
} */

void test_smolNoice(void){
  smolcert_t* clientCert = (smolcert_t*)calloc(1, sizeof(smolcert_t));
  sc_error_t err = SN_OK;
  sn_buffer_t* clientCertBuffer = sn_buffer_new(256);
  smolNoice_t* smolNoiceTest;
  uint8_t privateKeyBuffer[32];
  char certFilePath[CWD_BUF_SIZE];
  char keyFilePath[CWD_BUF_SIZE];
  getcwd(certFilePath, CWD_BUF_SIZE);
  getcwd(keyFilePath, CWD_BUF_SIZE);
  strcat(certFilePath,CERT_PATH);
  strcat(keyFilePath,KEY_PATH);
  
  err =  loadSmolCert(certFilePath, clientCert, clientCertBuffer);
  sn_buffer_rewind(clientCertBuffer);
  TEST_ASSERT_EQUAL(err , Sc_No_Error);

  err = loadPrivateKey(keyFilePath,privateKeyBuffer);
  if(err != Sc_No_Error) return;

  smolNoiceTest = smolNoice();
  if(smolNoiceTest == NULL) return; 

  err = sn_set_host(smolNoiceTest,"127.0.0.1", 9095);
  if(err != Sc_No_Error) return;

  err = sn_set_client_cert(smolNoiceTest, clientCertBuffer->idx, clientCertBuffer->len);
  if(err != Sc_No_Error) return;

  err = sn_set_client_priv_key(smolNoiceTest, privateKeyBuffer);
  if(err != Sc_No_Error) return;

  if(err != Sc_No_Error) return;

  err = sn_connect(smolNoiceTest);
  TEST_ASSERT_EQUAL_MESSAGE(SN_OK, err, "Connect failed");

   char testBuffer[32];
   uint8_t receiveBuffer[32];
   uint32_t i = 5;
  while(i < 1024){
    // sleep_ms(50);
    //usleep(10000);
    sprintf(testBuffer,"ping %d", i++);
    printf("Sending data: %s\n", testBuffer);
    int n = sn_send(smolNoiceTest, (uint8_t*)testBuffer, strlen(testBuffer));
    if(n<0) {
      printf("Failed sending data\n");
      break;
    }
    printf("Waiting to receive data\n");
    n = sn_recv(smolNoiceTest, receiveBuffer, 32);
    if(n < 0) {
      printf("Failed to read data\n");
      TEST_FAIL_MESSAGE("Failed to read data");
      break;
    }
    printf("Received data: %s\n", receiveBuffer);
    TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(testBuffer, receiveBuffer, n, "Echoed data does not match received data");
  }
  sn_buffer_free(clientCertBuffer);
  sn_disconnect(smolNoiceTest);
    printf("End");
}

int main(void) {
    if (sodium_init() == -1) {
      return 1;
    }
    UNITY_BEGIN();
    
    RUN_TEST(test_readWriteUint16);
    RUN_TEST(test_writeLVBlock);
    RUN_TEST(test_readLVBlock);
    RUN_TEST(test_packHandshakeInit);
    RUN_TEST(test_unpackHandshakeResponse);
    RUN_TEST(test_NoiseName);
    RUN_TEST(test_packHandshakeFin);
    RUN_TEST(test_bufferPadding);
    //RUN_TEST(test_smolNoice);
    

    return UNITY_END();
    
    //return 0;
}



// Utility
sc_error_t loadSmolCert(const char* fileName, smolcert_t* cert, sn_buffer_t* buffer){
  FILE *fp;
  
  sc_error_t sc_err;
  fp = fopen(fileName,"rb");

  if(fp == NULL){
    TEST_FAIL_MESSAGE("File not found");
  }
  
  fseek(fp,0,SEEK_END);
  size_t file_length = ftell(fp);

  rewind(fp);
  sn_buffer_ensure_cap(buffer, file_length);
  buffer->len += fread(buffer->idx, 1, file_length, fp);
  fclose(fp);

  sc_err = sc_parse_certificate(buffer->idx,buffer->len, cert);
  if(sc_err != SN_OK) {
    TEST_FAIL_MESSAGE("Failed to parse smolcert");
  }

  return sc_err;
}

sn_err_t loadPrivateKey(const char* fileName, uint8_t* privateKey){
  FILE *fp;
  fp = fopen(fileName,"rb");
  
  if(fp == NULL){
    TEST_FAIL_MESSAGE("File not found");
  }
  fread(privateKey, 32, 1, fp);
  fclose(fp);

  return SN_OK;
}
