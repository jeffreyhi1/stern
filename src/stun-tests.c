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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "stun.h"

const char *
test_message_type(struct stun_message *stun, int type)
{
    if (!stun)
        return "FAIL (No response)";

    if (stun->message_type != type)
        return "FAIL (Message type incorrect)";

    return NULL;
}

const char *
test_mapped_address(struct stun_message *stun, struct sockaddr *addr)
{
    if (!stun->mapped_address)
        return "FAIL (No mapped address)";

    if (stun->mapped_address->sa_family != addr->sa_family)
        return "FAIL (Mapped address family incorrect)";

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sins = (struct sockaddr_in *)stun->mapped_address;
        struct sockaddr_in *sina = (struct sockaddr_in *)addr;
        if (sins->sin_addr.s_addr != sina->sin_addr.s_addr)
            return "FAIL (Incorrect mapped address)";
        if (sins->sin_port != sina->sin_port)
            return "FAIL (Incorrect mapped port)";
    }

    return NULL;
}


