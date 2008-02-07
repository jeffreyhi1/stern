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
#include "sternd.h"

struct sternd sternd;

//------------------------------------------------------------------------------
void
sternd_init()
{
    static int initialized = 0;

    if (initialized)
        return;

    memset(&sternd, 0, sizeof(sternd));
    sternd.stuntcp.sock = -1;
    sternd.stunudp.sock = -1;
    LIST_INIT(&sternd.stuntcp.clients);
    LIST_INIT(&sternd.stunudp.clients);
    sternd.stuntcp.sternd = &sternd;
    sternd.stunudp.sternd = &sternd;
    sternd.stuntcp.protocol = IPPROTO_TCP;
    sternd.stunudp.protocol = IPPROTO_UDP;

    sternd.turntcp.sock = -1;
    LIST_INIT(&sternd.turntcp.clients);
    sternd.turntcp.sternd = &sternd;
    sternd.turntcp.protocol = IPPROTO_TCP;

    sternd.base = event_init();

    initialized = 1;
}

//------------------------------------------------------------------------------
void
sternd_dispatch()
{
    event_base_dispatch(sternd.base);
}

//------------------------------------------------------------------------------
void
sternd_loop()
{
    int i;
    struct timeval tv = {0, 10000};

    for (i = 0; i < 5; i++) {
        event_base_loopexit(sternd.base, &tv);
        event_base_loop(sternd.base, EVLOOP_NONBLOCK);
    }
}

//------------------------------------------------------------------------------
void
sternd_quit()
{
    sternd_stun_quit();
    sternd_turn_quit();
    sternd_init();
}
