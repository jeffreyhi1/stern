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
#ifndef __STERND_H
#define __STERND_H

#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include <stern/stun.h>
#include <stern/turn.h>

#include "config.h"
#include "const.h"
#include "internal.h"

#define CLIENT_TIMEOUT 120

void *stun_tcp_init();
void *stun_udp_init();
void *turn_tcp_init();

#endif
