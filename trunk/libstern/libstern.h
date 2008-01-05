#ifndef __LIBSTERN_H
#define __LIBSTERN_H

#include <time.h>
#include <zlib.h>
#include <openssl/hmac.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "config.h"
#include "const.h"
#include "stun.h"
#include "turn.h"
#include "internal.h"

const char *stun_error_reason(int error_code);

#endif

