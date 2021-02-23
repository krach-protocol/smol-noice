#ifdef INC_FREERTOS_H
/**
 * This smells kind of fishy, since it checks for a header not a compiler variable
 * Means this MUST be included AFTER freeRTOS headers
 * */ 
#include "lwip/sockets.h"


#include "sn_queue.h"
#include "sn_msg.h"

sn_queue_err_t initQueues();
sn_queue_err_t QueueReceive(sn_msg_t *rxMsg);
sn_queue_err_t QueueTransmit(sn_msg_t *txMsg);

#endif