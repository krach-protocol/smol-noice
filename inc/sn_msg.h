#ifndef _SN_MSG_H_
#define _SN_MSG_H_


#include <inttypes.h>
#include "sn_err.h"

typedef struct{
    uint8_t* _orig_ptr;
    uint8_t* idx;
    size_t _cap;
    size_t len;
} sn_msg_t,sn_buffer_t;

/**
 * @brief Creates a new buffer structure with the specified capacity
 * 
 * @param _cap capacity of the buffer in bytes
 * @return sn_buffer_t* 
 */
sn_buffer_t* sn_buffer_new(size_t _cap);
/**
 * @brief Frees an existing buffer.
 * 
 * @param buf 
 */
void sn_buffer_free(sn_buffer_t* buf);
/**
 * @brief Resets an existing buffer for reuse. This does not null the underlying memory!
 * 
 * @param buf 
 */
void sn_buffer_reset(sn_buffer_t* buf);
/**
 * @brief Resizes an existing buffer to the new capacity. If new_len is smaller than the old
 * capacity this will lead to data loss. Existing data is kept for all elements which still 
 * fit into the new capacity
 * 
 * @param buf 
 * @param new_len 
 */
void sn_buffer_resize(sn_buffer_t* buf, size_t new_len);
/**
 * @brief Copies data into the given buffer by appending it to the end. This will automatically
 * resize the given buffer to fit all elements
 * 
 * @param buf 
 * @param in_buf 
 * @param len 
 */
void sn_buffer_copy_into(sn_buffer_t *buf, uint8_t* in_buf, size_t len);

/**
 * @brief Ensure that the given buffer has at least capacity for the expected amount of data
 * 
 * @param buf 
 * @param expected_cap 
 */
void sn_buffer_ensure_cap(sn_buffer_t *buf, size_t expected_cap);

//Padding
sn_err_t padBuffer(sn_buffer_t*);
sn_err_t unpadBuffer(sn_buffer_t*);


#endif