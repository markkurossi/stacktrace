/*
 *
 * gnumalloc.c
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
 * the Free Software Foundation; either version 2, or (at your option)
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

#include "gnuincludes.h"

void *
gnu_malloc(size_t size)
{
  return malloc(size);
}


void *
gnu_calloc(size_t number, size_t size)
{
  return calloc(number, size);
}


void *
gnu_realloc(void *ptr, size_t size)
{
  if (ptr == NULL)
    return malloc(size);

  return realloc(ptr, size);
}


void
gnu_free(void *ptr)
{
  if (ptr == NULL)
    return;

  free(ptr);
}


char *
gnu_strdup(const char *str)
{
  return strdup(str);
}


void *
gnu_memdup(const void *data, size_t len)
{
  unsigned char *ptr;

  ptr = gnu_malloc(len + 1);
  if (ptr == NULL)
    return NULL;

  memcpy(ptr, data, len);
  ptr[len] = '\0';

  return ptr;
}

#define GNU_MALLOC_CHECK(ptr, what)             \
do                                              \
  {                                             \
    if ((ptr) == NULL)                          \
      {                                         \
        fprintf(stderr, "%s failed\n", (what)); \
        abort();                                \
      }                                         \
  }                                             \
while (0)


void *
gnu_xmalloc(size_t size)
{
  void *ptr = gnu_malloc(size);

  GNU_MALLOC_CHECK(ptr, "gnu_xmalloc");
  return ptr;
}


void *
gnu_xcalloc(size_t number, size_t size)
{
  void *ptr = gnu_calloc(number, size);

  GNU_MALLOC_CHECK(ptr, "gnu_xcalloc");
  return ptr;
}


void *
gnu_xrealloc(void *ptr, size_t size)
{
  void *nptr = gnu_realloc(ptr, size);

  GNU_MALLOC_CHECK(nptr, "gnu_xrealloc");
  return nptr;
}


void
gnu_xfree(void *ptr)
{
  gnu_free(ptr);
}


char *
gnu_xstrdup(const char *str)
{
  char *nstr = gnu_strdup(str);

  GNU_MALLOC_CHECK(str, "gnu_xstrdup");
  return nstr;
}


void *
gnu_xmemdup(const void *data, size_t len)
{
  void *ptr = gnu_memdup(data, len);

  GNU_MALLOC_CHECK(ptr, "gnu_xmemdup");
  return ptr;
}
