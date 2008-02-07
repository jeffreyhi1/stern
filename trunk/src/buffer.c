#include <string.h>
#include <sys/socket.h>

#include "internal.h"

//------------------------------------------------------------------------------
void
b_init(struct buffer *buf)
{
    memset(buf, 0, sizeof(struct buffer));
}

//------------------------------------------------------------------------------
void
b_reset(struct buffer *buf)
{
    s_free(buf->bytes);
    b_init(buf);
}

//------------------------------------------------------------------------------
void
b_grow(struct buffer *buf)
{
    buf->size *= 2;
    if (buf->size == 0)
        buf->size = BUFFER_MIN;
    buf->bytes = s_realloc(buf->bytes, buf->size);
}

//------------------------------------------------------------------------------
void
b_shrink(struct buffer *buf)
{
    if (buf->pos == buf->len) {
        b_reset(buf);
    } else {
        buf->len -= buf->pos;
        memmove(buf->bytes, buf->bytes + buf->pos, buf->len);
        buf->pos = 0;
        if (buf->len < buf->size / 2) {
            buf->size /= 2;
            buf->bytes = s_realloc(buf->bytes, buf->size);
        }
    }
}

ssize_t
b_recv(struct buffer *buf, int fd, size_t max, int flags)
{
    ssize_t ret, len;

    max = max == 0 ? BUFFER_MAX : max;
    if (b_num_free(buf) == 0)
        b_grow(buf);
    len = b_num_free(buf) > max ? max : b_num_free(buf);
    len = recv(fd, b_pos_free(buf), len, flags);
    if (len <= 0) return len;
    b_used_free(buf, len);
    max -= len;

    while (max > 0 && b_num_free(buf) == 0 && buf->size < BUFFER_MAX) {
        b_grow(buf);
        ret = b_num_free(buf) > max ? max : b_num_free(buf);
        ret = recv(fd, b_pos_free(buf), ret, flags | MSG_DONTWAIT);
        if (ret <= 0) return len;
        b_used_free(buf, ret);
        len += ret;
        max -= ret;
    };

    return len;
}

ssize_t
b_send(struct buffer *buf, int fd, int flags)
{
    ssize_t ret, len = 0;

    while (b_num_avail(buf)) {
        ret = send(fd, b_pos_avail(buf), b_num_avail(buf), flags);
        if (ret <= 0) break;
        b_used_avail(buf, ret);
        len += ret;
    }
    if (b_num_avail(buf) < buf->size / 2)
        b_shrink(buf);

    return len > 0 ? len : ret;
}
