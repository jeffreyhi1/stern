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

//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    int stuntcp, stunudp, turntcp;

    sternd_init();

    stuntcp = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    stunudp = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    turntcp = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    sternd_set_stun_socket(IPPROTO_TCP, stuntcp, PORT_STUN);
    sternd_set_stun_socket(IPPROTO_UDP, stunudp, PORT_STUN);
    sternd_set_turn_socket(IPPROTO_TCP, turntcp, PORT_TURN);

    sternd_dispatch();

    return 0;
}
