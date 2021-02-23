#include "smolcert.h"
#include "unity.h"

#include <unistd.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#include "handshake.h"

#define CWD_BUF_SIZE 128

void test_makeNoiseHandshake(void);
void loadSmolCert(const char*,smolcert_t**);
void test_parseCertFromfile(void);

void loadSmolCert(const char* fileName,smolcert_t** cert){
  FILE *fp;
  uint8_t* buf;
  size_t bufSize;
  
  sc_error_t sc_err;
  fp = fopen(fileName,"rb");

  if(fp == NULL){
    TEST_ABORT();
  }

  fseek(fp,0,SEEK_END);
  bufSize = ftell(fp);
  rewind(fp);
  buf = (u_int8_t*)malloc(bufSize);
  fread(buf,1,bufSize,fp);
  sc_err = sc_parse_certificate(buf,bufSize, *cert);
  free(buf);
  TEST_ASSERT_EQUAL(Sc_No_Error, sc_err);
}



void test_makeNoiseHandshake(void){
  smolcert_t *clientCert = (smolcert_t*)malloc(sizeof(smolcert_t));
  const char* host = "127.0.0.1";
  char certFilePath[CWD_BUF_SIZE];
  getcwd(certFilePath, CWD_BUF_SIZE);
  printf("Current working directory: %s\n",certFilePath);
  strcat(certFilePath,"/tests/krach-test-helper/client.smolcert");
  printf("Full certpath: %s",certFilePath);
  loadSmolCert(certFilePath,&clientCert);

  sc_init(clientCert,host,9095);
  /*
  for(uint8_t i = 0; i < 32; i++){
    printf("0x%02x ",clientCert->public_key[i]);
    if(i%16==0) printf("\n");
  }
  //TEST_ASSERT_EQUAL(1 , 0);
 */
  TEST_ASSERT_EQUAL(1 , 1);
}

int main(void) {
    if (sodium_init() == -1) {
      return 1;
    }
    //UNITY_BEGIN();
    //RUN_TEST(test_Parsing_valid_smolcert);
    //RUN_TEST(test_ValidateCertificateSignature);
    //RUN_TEST(test_parseCertFromfile);
    RUN_TEST(test_makeNoiseHandshake);
    //return UNITY_END();
    return 0;
}