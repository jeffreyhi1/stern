/**
 * Copyright (C) 2007 Saikat Guha <saikat@cs.cornell.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __COMMON_H
#define __COMMON_H

#include <sys/types.h>
#include <arpa/inet.h>

#define BUFFER_MIN     256
#define BUFFER_MAX     8192

struct buffer {
    size_t len;
    size_t pos;
    size_t size;
    void *bytes;
};

void *s_malloc(size_t len);
void *s_realloc(void *ptr, size_t len);
void s_free(void *ptr);

void b_init(struct buffer *buf);
void b_reset(struct buffer *buf);
void b_grow(struct buffer *buf);
void b_shrink(struct buffer *buf);
#define b_is_empty(buf)           ((buf)->len  == (buf)->pos)
#define b_pos_avail(buf)          ((buf)->bytes + (buf)->pos)
#define b_num_avail(buf)          ((buf)->len   - (buf)->pos)
#define b_used_avail(buf, num)    do { (buf)->pos += (num); } while(0)
#define b_pos_free(buf)           ((buf)->bytes + (buf)->len)
#define b_num_free(buf)           ((buf)->size  - (buf)->len)
#define b_used_free(buf, num)     do { (buf)->len += (num); } while(0)
ssize_t b_recv(struct buffer *buf, int fd, size_t max, int flags);
ssize_t b_send(struct buffer *buf, int fd, int flags);

int sockaddr_matches(struct sockaddr *addr1, struct sockaddr *addr2);
int sockaddr_matches_addr(struct sockaddr *addr1, struct sockaddr *addr2);

#endif
