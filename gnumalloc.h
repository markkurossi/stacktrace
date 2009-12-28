/*
 *
 * gnumalloc.h
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

#ifndef GNUMALLOC_H
#define GNUMALLOC_H

/* XXX */
void *gnu_malloc(size_t size);

/* XXX */
void *gnu_calloc(size_t number, size_t size);

/* XXX */
void *gnu_realloc(void *ptr, size_t size);

/* XXX */
void gnu_free(void *ptr);

/* XXX */
char *gnu_strdup(const char *str);

/* XXX */
void *gnu_memdup(const void *data, size_t len);

/* XXX */
void *gnu_xmalloc(size_t size);

/* XXX */
void *gnu_xcalloc(size_t number, size_t size);

/* XXX */
void *gnu_xrealloc(void *ptr, size_t size);

/* XXX */
void gnu_xfree(void *ptr);

/* XXX */
char *gnu_xstrdup(const char *str);

/* XXX */
void *gnu_xmemdup(const void *data, size_t len);

#endif /* GNUMALLOC_H */
