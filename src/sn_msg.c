#include "sn_msg.h"

#include <stdlib.h>
#include <string.h>

sn_buffer_t* sn_buffer_new(size_t _cap){
    sn_buffer_t* buf = (sn_buffer_t*)malloc(sizeof(sn_buffer_t));
    buf->_orig_ptr = (uint8_t*)malloc(_cap);
    buf->idx = buf->_orig_ptr;
    buf->_cap = _cap;
    buf->len = 0;
    return buf;
}

void sn_buffer_free(sn_buffer_t* buf) {
    free(buf->_orig_ptr);
    free(buf);
}

void sn_buffer_reset(sn_buffer_t* buf) {
    buf->idx = buf->_orig_ptr;
    buf->len = 0;
}

void sn_buffer_resize(sn_buffer_t* buf, size_t new_len) {
    size_t idx_offset = buf->idx - buf->_orig_ptr;
    buf->_orig_ptr = realloc(buf->_orig_ptr, new_len);
    if(idx_offset >= new_len) {
        // If we reduce the buffer size, the current index maybe outside of the
        // new capacity, therefore we set the offset to 0 to point idx to the beginning 
        // of the buffer
        idx_offset = 0;
    }
    buf->idx = buf->_orig_ptr + idx_offset;
    buf->_cap = new_len;
    if((idx_offset + buf->len) > new_len) {
        buf->len = new_len - idx_offset;
    }
}

void sn_buffer_copy_into(sn_buffer_t *buf, uint8_t* in_buf, size_t len) {
    if((buf->_cap - buf->len) < len) {
        sn_buffer_resize(buf, (len-(buf->_cap - buf->len)));
    }
    memcpy((buf->idx+buf->len), in_buf, len);
}

void sn_buffer_ensure_cap(sn_buffer_t *buf, size_t expected_cap) {
    if((buf->_cap - (buf->idx - buf->_orig_ptr)) < expected_cap) {
        size_t cap_needed = expected_cap - (buf->_cap - (buf->idx - buf->_orig_ptr));
        size_t new_cap = buf->_cap + cap_needed;
        sn_buffer_resize(buf, new_cap);
    }
}

sc_err_t padBuffer(sn_buffer_t* buf){
    uint8_t bytes_to_pad = (uint8_t)(buf->len+1)%16;
    size_t new_len = buf->len + 1 /*pad header */ + bytes_to_pad;
    sn_buffer_ensure_cap(buf, new_len);
    // TODO this needs to be optimized. Move every element one to the right
    for(size_t i = buf->len+1; i>0; i--) {
        buf->idx[i] = buf->idx[i-1];
    }
    buf->idx[0] = bytes_to_pad;

    return SC_OK;

}
sc_err_t unpadBuffer(sn_buffer_t* buf){
    uint8_t padded_bytes = buf->idx[0];
    buf->len = buf->len - 1 /*padding header*/ - padded_bytes;
    buf->idx = buf->idx + 1;

    return SC_OK;
}