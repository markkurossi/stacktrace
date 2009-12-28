/*
 *
 * gnuglob.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2001 Markku Rossi.
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

#ifndef GNUGLOB_H
#define GNUGLOB_H

/* XXX */
GnuBool gnu_glob_match(const char *pattern, const char *string);

/* XXX */
GnuBool gnu_glob_match_data(const char *pattern, size_t pattern_len,
                            const char *string, size_t string_len);

#endif /* GNUGLOB_H */
