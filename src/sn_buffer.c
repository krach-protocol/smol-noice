#include "sn_buffer.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

sn_buffer_t* sn_buffer_new(size_t _cap){
    sn_buffer_t* buf = (sn_buffer_t*)calloc(1, sizeof(sn_buffer_t));
    buf->_orig_ptr = (uint8_t*)calloc(1, _cap);
    buf->idx = buf->_orig_ptr;
    buf->_cap = _cap;
    buf->len = 0;
    return buf;
}

void sn_buffer_free(sn_buffer_t* buf) {
    if(buf != NULL) {
        if(buf->_orig_ptr != NULL) {
            free(buf->_orig_ptr);
        }
        free(buf);
    }
}

void sn_buffer_reset(sn_buffer_t* buf) {
    buf->idx = buf->_orig_ptr;
    buf->len = 0;
}

void sn_buffer_rewind(sn_buffer_t *buf) {
    buf->len = buf->idx - buf->_orig_ptr + buf->len;
    buf->idx = buf->_orig_ptr;
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

void sn_buffer_write_into(sn_buffer_t *buf, uint8_t* in_buf, size_t len) {
    sn_buffer_write(buf, in_buf, len);
}

void sn_buffer_ensure_cap(sn_buffer_t *buf, size_t expected_cap) {
    if((buf->_cap - (buf->idx - buf->_orig_ptr)) < expected_cap) {
        size_t cap_needed = expected_cap - (buf->_cap - (buf->idx - buf->_orig_ptr));
        size_t new_cap = buf->_cap + cap_needed;
        sn_buffer_resize(buf, new_cap);
    }
}

void sn_buffer_write(sn_buffer_t *buf, uint8_t* data, size_t data_len) {
    sn_buffer_ensure_cap(buf, data_len);
    memcpy(buf->idx, data, data_len);
    buf->idx += data_len;
    buf->len = 0;
}

void sn_buffer_write_uint16(sn_buffer_t* buf, uint16_t val) {
    sn_buffer_ensure_cap(buf, 2);
    buf->idx[0] = (val & 0x00FF);
    buf->idx[1] = (val & 0xFF00) >> 8;
    buf->idx += 2;
    buf->len = 0;
}

uint16_t sn_buffer_peek_lv_len(sn_buffer_t* buf) {
    uint16_t result = 0;
    if(buf->len < 1) {
        return 0;
    }
    result += buf->idx[0] | (buf->idx[1] << 8);
    return result;
}

sn_err_t sn_buffer_read_lv_block(sn_buffer_t* buf, uint8_t* dst, size_t dst_len) {
    uint16_t block_len = sn_buffer_peek_lv_len(buf);
    if(block_len == 0) {
        return SN_OK;
    }
    if(block_len > dst_len) {
        return SN_PAKET_ERR;
    }
    if(block_len+2 > buf->len) {
        return SN_PAKET_ERR;
    }
    memcpy(dst, buf->idx+2, block_len);
    buf->idx += (size_t)(block_len + 2);
    buf->len -= (block_len + 2);
    return SN_OK;
}

sn_err_t sn_buffer_read(sn_buffer_t* buf, uint8_t* dest, size_t len) {
    if(buf->len < len) {
        return SN_PAKET_ERR;
    }
    memcpy(dest, buf->idx, len);
    buf->idx += len;
    buf->len -= len;
    return SN_OK;
}

sn_err_t sn_buffer_read_uint16(sn_buffer_t* buf, uint16_t* dest) {
    if(buf->len < 2) {
        return SN_PAKET_ERR;
    }
    *dest = sn_buffer_peek_lv_len(buf);
    buf->idx += 2;
    buf->len -= 2;
    return SN_OK;
}

void sn_buffer_write_lv_block(sn_buffer_t* buf, uint8_t* src, uint16_t src_len) {
    sn_buffer_ensure_cap(buf, src_len+2);
    sn_buffer_write_uint16(buf, src_len);
    memcpy(buf->idx+buf->len, src, src_len);
    buf->idx += src_len;
}

sn_err_t sn_buffer_pad(sn_buffer_t* buf){
    size_t bytes_to_pad = 16 - (buf->len+1)%16;
    if(bytes_to_pad == 16) {
        bytes_to_pad = 0;
    }
    size_t new_len = buf->len + 1 /*pad header */ + bytes_to_pad;
    if(buf->_orig_ptr < buf->idx) {
        // We have space in front of our current pointer, we will use this
        sn_buffer_ensure_cap(buf, new_len - 1);
        buf->idx -= 1;

    } else {
        sn_buffer_ensure_cap(buf, new_len);
        for(size_t i = buf->len+1; i>0; i--) {
            buf->idx[i] = buf->idx[i-1];
        }
    }
    buf->idx[0] = (uint8_t)bytes_to_pad;
    for(size_t i = new_len-1; i>(new_len - bytes_to_pad); i--) {
        buf->idx[i] = 0;
    }
    buf->len = new_len;
    return SN_OK;

}
sn_err_t sn_buffer_unpad(sn_buffer_t* buf){
    uint8_t padded_bytes = buf->idx[0];
    buf->len = buf->len - 1 /*padding header*/ - padded_bytes;
    buf->idx = buf->idx + 1;

    return SN_OK;
}