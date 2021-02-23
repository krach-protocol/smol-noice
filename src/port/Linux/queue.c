#include "queue.h"

queue_err_e messageInQueue(queue_t* queue){
    if(queue->queueIdx == queue->queueLen-1){
        return FULL;
    }else if(queue->queueIdx > 0){
        return DATA_AVAILIBLE;
    }else{
        return EMPTY;
    }

}
queue_err_e getMessageFromQueue(queue_t* queue, void* data){
    if(queue->queueIdx == 0){
        return EMPTY;
    } else {
        data = queue->data[queue->queueIdx];
        queue->queueIdx--;
        return OK;
    return 0;
    }
}
queue_err_e addToQueue(queue_t* queue, void* data){
return OK;
}
