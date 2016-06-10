/*
 *
 * piincludes.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003-2016 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Top-level include file for the PI programming environment.
 *
 */

#ifndef PIINCLUDES_H
#define PIINCLUDES_H

#include "piconf.h"

#define ENABLE_DEBUG 1
#define HAVE_STRING_H 1
#define HAVE_UNISTD_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#if HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#if HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "pimalloc.h"
#include "pifatal.h"


/************************** Types and definitions ***************************/

#define PI_ASSERT(what) assert(what)

#ifndef HAVE_BOOL
/* Define the boolean type. */
typedef unsigned char bool;

/* Define true and false. */
#define true  1
#define false 0
#endif /* not HAVE_BOOL */


typedef unsigned char PiUInt8;
typedef signed char PiInt8;

typedef unsigned short PiUInt16;
typedef signed short PiInt16;

typedef unsigned int PiUInt32;
typedef signed int PiInt32;

#ifdef _MSC_VER

#define PI_CONST_INT64(x) x
#define PI_CONST_UINT64(x) x

typedef unsigned __int64 PiUInt64;
typedef signed __int64 PiInt64;

/* Fetch some missing symbols from Windows' CRT. */
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define strtoll _strtoi64

#else /* not _MSC_VER */

#define PI_CONST_INT64(x) x##LL
#define PI_CONST_UINT64(x) x##ULL

typedef unsigned long long PiUInt64;
typedef signed long long PiInt64;

#endif /* not _MSC_VER */

/* Alignment requirements for different types. */
#define PI_ALIGN_UINT8	1
#define PI_ALIGN_UINT16	2
#define PI_ALIGN_UINT32	4
#define PI_ALIGN_UINT64	8
#define PI_ALIGN_UINT64	8
#define PI_ALIGN_PTR	4
#define PI_ALIGN_FLOAT	4
#define PI_ALIGN_DOUBLE	8

/******************************* Handy macros *******************************/

/* Align `number' to `align'.  The `number' and `align' must be
   integer numbers. */
#define PI_ALIGN(number, align) \
((((number) + ((align) - 1)) / (align)) * (align))

#endif /* not PIINCLUDES_H */
