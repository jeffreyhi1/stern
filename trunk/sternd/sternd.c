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

    if (!initialized) {
        event_init();
    }

    memset(&sternd, 0, sizeof(sternd));
    sternd.stuntcp.sock = -1;
    sternd.stunudp.sock = -1;
    LIST_INIT(&sternd.stuntcp.clients);
    LIST_INIT(&sternd.stunudp.clients);

    initialized = 1;
}

//------------------------------------------------------------------------------
void
sternd_dispatch()
{
    event_dispatch();
}

//------------------------------------------------------------------------------
void
sternd_loop()
{
    int i;
    struct timeval tv = {0, 10000};

    for (i = 0; i < 5; i++) {
        event_loopexit(&tv);
        event_loop(EVLOOP_NONBLOCK);
    }
}

//------------------------------------------------------------------------------
void
sternd_quit()
{
    sternd_stun_quit();
    sternd_init();
}
