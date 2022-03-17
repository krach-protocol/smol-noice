#ifndef _SMOL_NOICE_H_
#define _SMOL_NOICE_H_

#include "sn_err.h"
#include "smolcert.h"
typedef struct smolNoice smolNoice_t;


smolNoice_t* smolNoice(void);
sn_err_t sn_connect(smolNoice_t* smol_noice);

sc_err_t sn_set_host(smolNoice_t* smolNoice,const char* hostAddress,uint16_t hostPort);
sc_err_t sn_set_client_cert(smolNoice_t* smolNoice, uint8_t* clientCert,uint8_t clientCertLen);
sc_err_t sn_set_client_priv_key(smolNoice_t* smolNoice,uint8_t* privateKey);
sc_err_t sn_set_remote_cert_callback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t,smolcert_t*));

int sn_send(smolNoice_t* smol_noice, uint8_t* buf, size_t buf_len);

sc_err_t smolNoiceSendData(smolNoice_t* smolNoice,uint8_t dataLen,uint8_t* data);

sc_err_t smolNoiceReadyForTransport(smolNoice_t* smolNoice);


sc_err_t smolNoiceDelete(smolNoice_t*);

#endif