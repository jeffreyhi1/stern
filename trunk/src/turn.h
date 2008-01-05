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
#ifndef __TURN_H
#define __TURN_H

typedef void * turn_socket_t;

turn_socket_t
turn_socket(int family, int type, int protocol);

int
turn_init(turn_socket_t socket, struct sockaddr *addr, socklen_t len);

int
turn_connect(turn_socket_t socket, struct sockaddr *addr, socklen_t len);

int
turn_listen(turn_socket_t socket, int limit);

int
turn_getsockname(turn_socket_t socket, struct sockaddr *addr, socklen_t *len);

int
turn_permit(turn_socket_t socket, struct sockaddr *addr, socklen_t len);

ssize_t
turn_recvfrom(turn_socket_t socket, char *buf, size_t len, struct sockaddr *addr, socklen_t *alen);

int
turn_sendto(turn_socket_t socket, char *buf, size_t len, struct sockaddr *addr, socklen_t alen);

void
turn_close(turn_socket_t socket);

#endif
