#ifndef _SC_HANDSHAKE_H_
#define _SC_HANDSHAKE_H_
typedef enum errorType {SC_OK=0,SC_ERR} sc_err_t;

sc_err_t sc_init(void);
sc_err_t sc_destory(void);

#endif