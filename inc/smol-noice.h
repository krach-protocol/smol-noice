#ifndef _SMOL_NOICE_H_
#define _SMOL_NOICE_H_

#include "sn_err.h"
#include "smolcert.h"

#ifndef SN_MAX_FRAME_SIZE
#define SN_MAX_FRAME_SIZE 1400
#endif
typedef struct smolNoice smolNoice_t;


smolNoice_t* smolNoice(void);
sn_err_t sn_connect(smolNoice_t* smol_noice);

sc_err_t sn_set_host(smolNoice_t* smolNoice,const char* hostAddress,uint16_t hostPort);
sc_err_t sn_set_client_cert(smolNoice_t* smolNoice, uint8_t* clientCert,uint8_t clientCertLen);
sc_err_t sn_set_client_priv_key(smolNoice_t* smolNoice,uint8_t* privateKey);
sc_err_t sn_set_remote_cert_callback(smolNoice_t* smolNoice,sc_err_t (*dataCb)(uint8_t*,uint8_t,smolcert_t*));

/**
 * @brief Send data via the encrypted krach connection. Returns the amount of bytes send ot less than 0
 * to indicate an error
 * 
 * @param smol_noice 
 * @param buf 
 * @param buf_len 
 * @return int 
 */
int sn_send(smolNoice_t* smol_noice, uint8_t* buf, size_t buf_len);
/**
 * @brief Receive data from the encrypted krach connection. buf needs to be
 * at least large enough to hold SN_MAX_FRAME_SIZE bytes. Returns the amount of received
 * unencrypted data, or less than 0 to indicate an error.
 * 
 * @param smol_noice 
 * @param buf 
 * @param buf_len 
 * @return int 
 */
int sn_recv(smolNoice_t* smol_noice, uint8_t* buf, size_t buf_len);

void sn_free(smolNoice_t*);

#endif