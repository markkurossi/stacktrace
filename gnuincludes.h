/*
 *
 * gnuincludes.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2001-2009 Markku Rossi.
 *
 * What is this file for?
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef GNUINCLUDES_H
#define GNUINCLUDES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "gnudebug.h"
#include "gnumalloc.h"

/************************** Types and definitions ***************************/

typedef signed char GnuInt8;
typedef unsigned char GnuUInt8;
typedef short GnuInt16;
typedef unsigned short GnuUInt16;

typedef int GnuInt32;
typedef unsigned int GnuUInt32;

#ifndef TRUE
#define TRUE 1
#endif /* not TRUE */

#ifndef FALSE
#define FALSE 0
#endif /* not FALSE */

typedef int GnuBool;

#endif /* not GNUINCLUDES_H */
