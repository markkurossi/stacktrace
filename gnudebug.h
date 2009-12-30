/*
 *
 * gnudebug.h
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

#ifndef GNUDEBUG_H
#define GNUDEBUG_H

/************************** Types and definitions ***************************/

struct GnuDebugModuleRec
{
  struct GnuDebugModuleRec *next;

  const char *name;

  unsigned int initialized : 1;
  unsigned int debug_level : 8;
};

typedef struct GnuDebugModuleRec GnuDebugModuleStruct;
typedef struct GnuDebugModuleRec *GnuDebugModule;

#ifdef _MSC_VER

/* Fetch some missing symbols from Windows' CRT. */
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define strtoll _strtoi64

#endif /* _MSC_VER */

#ifdef __GNUC__
#define GNU__FUNCTION__ __FUNCTION__
#endif /* __GNUC__ */

#if !defined(GNU__FUNCTION__)
#define GNU__FUNCTION__ "<unknown>"
#endif /* not GNU__FUNCTION__ */


#define GNU_DEBUG_MODULE(name)                  \
static GnuDebugModuleStruct gnu_debug_module =  \
{                                               \
  NULL,                                         \
  name,                                         \
  0,                                            \
  0,                                            \
}

#define GNU_DEBUG(level, vacall)                        \
do                                                      \
  {                                                     \
    if (!gnu_debug_module.initialized)                  \
      gnu_debug_init_module(&gnu_debug_module);         \
                                                        \
    if (gnu_debug_module.debug_level >= (level))        \
      {                                                 \
        gnu_debug_lock();                               \
        gnu_debug_set_line(__FILE__, __LINE__);         \
        gnu_debug_set_function(GNU__FUNCTION__);        \
        gnu_debug vacall;                               \
        gnu_debug_unlock();                             \
      }                                                 \
  }                                                     \
while (0)

/******************************* Debug levels *******************************/

#define GNU_D_ERROR     0


/************************ Public debugging functions ************************/

/* XXX */
void gnu_debug_set_level_string(const char *string);

/* XXX */
void gnu_debug(char *fmt, ...);


/***************** Prototypes for internal debug functions ******************/

/* XXX */
void gnu_debug_init_module(GnuDebugModule module);

void gnu_debug_lock(void);

void gnu_debug_unlock(void);

void gnu_debug_set_line(const char *file, int line);

void gnu_debug_set_function(const char *function);


#endif /* not GNUDEBUG_H */
