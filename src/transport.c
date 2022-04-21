#include "transport.h"
#include "smol-noice-internal.h"
#include "sn_err.h"
#include "sn_buffer.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdlib.h>
#include <string.h>

void printHex(uint8_t*,uint8_t);
void printHex(uint8_t* key,uint8_t keyLen){
  for(uint8_t i = 0; i < keyLen; i++)
  {
    if(i%16 == 0) printf("\n");
    printf("%02x ",key[i]);
    
  }
  printf("\n");
  return;
}

uint8_t open_socket(smolNoice_t *smol_noice){
    struct addrinfo *res;
    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    char service[6];
    sprintf(service, "%d", smol_noice->hostPort);
    int err = getaddrinfo(smol_noice->hostAddress, service, &hints, &res);
    if(err != 0 || res == NULL) {
        return 1;
    }

    if ((smol_noice->socket = socket(res->ai_family, res->ai_socktype, 0)) < 0){
        printf("ERROR");
        return 1;	 
    }    

   if(connect(smol_noice->socket, res->ai_addr, res->ai_addrlen) < 0)
    {
       printf("Error : Connect Failed \n");
       return 1;
    }  
    return 0;
}
void close_socket(smolNoice_t* smol_noice) {
    close(smol_noice->socket);
}

/* This simply sends a complete buffer to the socket. No length prefixing or anything, but it ensures the
   the complete buffer is written */
sn_err_t sn_send_buffer(int socket, sn_buffer_t* buf) {
    size_t sent_bytes = 0;
    while(sent_bytes < buf->len) {
        int n = send(socket, buf->idx + sent_bytes, buf->len - sent_bytes, 0);
        if(n < 0) {
            return SN_NET_ERR;
        }
        sent_bytes += n;
    }
    return SN_OK;
}

sn_err_t sn_read_from_socket(int socket, sn_buffer_t* buf, size_t expected_length) {
    sn_buffer_ensure_cap(buf, expected_length);
    size_t bytes_read = 0;
    while(bytes_read < expected_length) {
        int n = recv(socket, buf->idx + bytes_read, expected_length - bytes_read, 0);
        if(n < 0) {
            return SN_NET_ERR;
        }
        bytes_read += n;
        buf->len += n;
    }
    return SN_OK;
}
