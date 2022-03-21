#include "transport.h"
#include "smol-noice-internal.h"
#include "sn_err.h"
#include "sn_buffer.h"
#include <stdio.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <string.h>

uint8_t open_socket(smolNoice_t *smolNoice){
    struct sockaddr_in serv_addr; 
    if ((smolNoice->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("ERROR");
        return 1;	 
    }    
	
    serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(smolNoice->hostPort);
	
    if(inet_pton(AF_INET,  smolNoice->hostAddress, &serv_addr.sin_addr)<=0) {
        printf("ERROR");
        return 1; 
    }
   
    printf("Connecting to: %s:%d\n",smolNoice->hostAddress,smolNoice->hostPort);
   if(connect(smolNoice->socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
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
    return SC_OK;
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
    return SC_OK;
}
