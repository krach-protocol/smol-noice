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

/**
 * @brief Writes data into the buffer and moves the pointer along, while maintaining a length 0.
 * 
 * @param buf 
 * @param data 
 * @param data_len 
 */
void sn_buffer_write(sn_buffer_t *buf, uint8_t* data, size_t data_len);

/**
 * @brief Rewinds the buffer after writing to it
 * 
 * @param buf 
 */
void sn_buffer_rewind(sn_buffer_t *buf);

/**
 * @brief Writes a uint16 with correct endianness to the buffer
 * 
 * @param buf 
 * @param val 
 */
void sn_buffer_write_uint16(sn_buffer_t* buf, uint16_t val);

/**
 * @brief If an lv buffer is expected at the current zero index of the buffer, return the length
 * without moving the index forward.
 * 
 * @param buf 
 * @return uint16_t 
 */
uint16_t sn_buffer_peek_lv_len(sn_buffer_t* buf);

/**
 * @brief Read the next expected lv block and move the index forward, therefore consuming parts of the buffer.
 * 
 * @param buf 
 * @param dst 
 * @param dst_len 
 */
sn_err_t sn_buffer_read_lv_block(sn_buffer_t* buf, uint8_t* dst, size_t dst_len);

/**
 * @brief Read len into dest buffer and move buffer forward
 * 
 * @param buf 
 * @param dest 
 * @param len 
 * @return sn_err_t 
 */
sn_err_t sn_buffer_read(sn_bufffer_t* buf, uint8_t* dest, size_t len);

/**
 * @brief Reads a uint16 from the buffer and moves it forward
 * 
 * @param buf 
 * @param dest 
 * @return sn_err_t 
 */
sn_err_t sn_buffer_read_uint16(sn_buffer_t* buf, uint16_t* dest);

void sn_buffer_write_lv_block(sn_buffert* buf, uint8_t* src, uint16_t src_len);

//Padding
sn_err_t padBuffer(sn_buffer_t*);
sn_err_t unpadBuffer(sn_buffer_t*);


#endif