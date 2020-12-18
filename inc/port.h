#ifndef _PORT_H_SC_
#define _PORT_H_SC_


#ifdef __linux__
    //Linux stuff
    #include <sys/socket.h> 
#elif ESP_PLATFORM
    //ESP stuff
    #include "lwip/sockets.h"

#else
    #error "This lib doesnt support your target system"
#endif 


#endif