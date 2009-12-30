/*
 *
 * gnuglob.c
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

#include "gnuincludes.h"
#include "gnuglob.h"

GNU_DEBUG_MODULE("GnuGlob");

GnuBool
gnu_glob_match(const char *pattern, const char *string)
{
  assert(pattern != NULL);
  assert(string != NULL);

  return gnu_glob_match_data(pattern, strlen(pattern),
                             string, strlen(string));
}


GnuBool
gnu_glob_match_data(const char *pattern, size_t pattern_len,
                    const char *string, size_t string_len)
{
  size_t i;

  while (1)
    {
      if (pattern_len == 0 && string_len == 0)
        return TRUE;

      if (pattern_len == 0 && string_len > 0)
        return FALSE;

      if (*pattern == '*')
        {
          /* Zero matches. */
          if (gnu_glob_match_data(pattern + 1, pattern_len - 1,
                                  string, string_len))
            return TRUE;

          /* One or more matches. */
          if (string_len == 0)
            return FALSE;

          if (gnu_glob_match_data(pattern, pattern_len,
                                  string + 1, string_len - 1))
            return TRUE;

          /* No match. */
          return FALSE;
          break;
        }
      else
        {
          GnuBool match;

          /* The string must have some data. */
          if (string_len == 0)
            return FALSE;

          switch (*pattern)
            {
            case '?':
              goto eat_one;
              break;

            case '[':
              match = FALSE;

              for (i = 0; i < pattern_len && pattern[i] != ']'; i++)
                {
                  if (*string == pattern[i])
                    match = TRUE;
                }
              if (i >= pattern_len)
                {
                  /* Malformed pattern, the ending `]' is missing. */
                  GNU_DEBUG(GNU_D_ERROR,
                            ("Malformed pattern `%.*s': "
                             "terminating `]' is missing",
                             (int) pattern_len, pattern));
                  return FALSE;
                }
              if (!match)
                return FALSE;

              /* Skip character class.  The terminating `]' is skipped at
                 `eat_one'. */
              pattern += i;
              pattern_len -= i;

              /* Eat one. */
              break;

            default:
              if (*pattern != *string)
                return FALSE;

              /* Eat one. */
              break;
            }

        eat_one:
          pattern++;
          pattern_len--;

          string++;
          string_len--;
          continue;
        }
    }

  /* NOTREACHED */
  return FALSE;
}
