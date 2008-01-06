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

