#ifndef _SMOL_NOICE_H_
#define _SMOL_NOICE_H_

#include "sc_err.h"
#include "smolcert.h"
typedef struct smolNoice smolNoice_t;


smolNoice_t* smolNoice(void);

sc_err_t smolNoiceSetHost(smolNoice_t* smolNoice,const char* hostAddress,uint16_t hostPort);
sc_err_t smolNoiceSetClientCert(smolNoice_t* smolNoice, uint8_t* clientCert,uint8_t clientCertLen);
sc_err_t smolNoiceStart(smolNoice_t*);

sc_err_t smolNoiceSendData(smolNoice_t* smolNoice,uint8_t dataLen,uint8_t* data);
sc_err_t smolNoiceSetTransportCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t));
sc_err_t smolNoiceSetRemoteCertCallback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t,smolcert_t*));

sc_err_t smolNoiceReadyForTransport(smolNoice_t* smolNoice);

sc_err_t smolNoiceDelete(smolNoice_t*);

#endif