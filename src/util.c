#include <assert.h>
#include <stdlib.h>

#include "internal.h"

//------------------------------------------------------------------------------
void *
s_malloc(size_t len)
{
    void *ptr = malloc(len);
    assert(ptr);
    return ptr;
}

//------------------------------------------------------------------------------
void *
s_realloc(void *ptr, size_t len)
{
    ptr = realloc(ptr, len);
    assert(ptr);
    return ptr;
}

//------------------------------------------------------------------------------
void
s_free(void *ptr)
{
    free(ptr);
}

//------------------------------------------------------------------------------
int
sockaddr_matches(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *sina = (struct sockaddr_in *) addr1;
    struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in *sinb = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *) addr2;

    if (addr1 && addr2 && addr1->sa_family == addr2->sa_family) {
        switch (addr1->sa_family) {
            case AF_INET:
                if (sina->sin_addr.s_addr == sinb->sin_addr.s_addr
                    && sina->sin_port == sinb->sin_port)
                    return 1;
                break;

            case AF_INET6:
                if (memcmp(sin6a->sin6_addr.s6_addr, sin6b->sin6_addr.s6_addr, 16) != 0)
                    break;
                if (sin6a->sin6_port == sin6b->sin6_port)
                    return 1;
            }
    }
    return 0;
}

//------------------------------------------------------------------------------
int
sockaddr_matches_addr(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *sina = (struct sockaddr_in *) addr1;
    struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in *sinb = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *) addr2;

    if (addr1 && addr2 && addr1->sa_family == addr2->sa_family) {
        switch (addr1->sa_family) {
            case AF_INET:
                if (sina->sin_addr.s_addr == sinb->sin_addr.s_addr)
                    return 1;
                break;

            case AF_INET6:
                if (memcmp(sin6a->sin6_addr.s6_addr, sin6b->sin6_addr.s6_addr, 16) != 0)
                    return 1;
                break;
            }
    }
    return 0;
}

