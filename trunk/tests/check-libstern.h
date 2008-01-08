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
#ifndef __CHECK_LIBSTERN_H
#define __CHECK_LIBSTERN_H

#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

#include <stern/stun.h>
#include "const.h"

#include <check.h>

Suite *check_parser();
Suite *check_stun();

#endif
