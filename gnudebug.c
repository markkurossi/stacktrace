/*
 *
 * gnudebug.c
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

#include "gnuincludes.h"
#include "gnuglob.h"

GNU_DEBUG_MODULE("GnuDebug");

/************************** Types and definitions ***************************/

struct GnuDebugSpecRec
{
  struct GnuDebugSpecRec *next;

  char *pattern;
  GnuUInt8 level;
};

typedef struct GnuDebugSpecRec GnuDebugSpecStruct;
typedef struct GnuDebugSpecRec *GnuDebugSpec;


/***************************** Static variables *****************************/

static GnuDebugModule debug_modules = NULL;

static GnuDebugSpec debug_specs = NULL;

/* The location of the current debug statement. */
static const char *current_file;
static int current_line;
static const char *current_function;

static char debug_buf[4096];


/************************ Public debugging functions ************************/

void
gnu_debug_set_level_string(const char *string)
{
  GnuDebugSpec s;
  const char *cp;

  /* Free old debug specs. */
  while (debug_specs)
    {
      s = debug_specs;
      debug_specs = debug_specs->next;

      gnu_free(s->pattern);
      gnu_free(s);
    }

  /* Uninit all modules. */
  while (debug_modules)
    {
      GnuDebugModule m;

      m = debug_modules;
      debug_modules = debug_modules->next;

      m->debug_level = 0;
      m->initialized = 0;
    }

  if (string == NULL)
    return;

  do
    {
      size_t len;
      char *sep;

      cp = strchr(string, ',');
      if (cp)
        len = cp - string;
      else
        len = strlen(string);

      s = gnu_calloc(1, sizeof(*s));
      if (s == NULL)
        {
        error_memory:
          GNU_DEBUG(GNU_D_ERROR, ("Out of memory"));
          return;
        }

      s->pattern = gnu_calloc(1, len + 1);
      if (s->pattern == NULL)
        {
          gnu_free(s);
          goto error_memory;
        }

      memcpy(s->pattern, string, len);

      /* It is not null-terminated. */

      sep = strchr(s->pattern, '=');
      if (sep == NULL)
        {
          GNU_DEBUG(GNU_D_ERROR, ("Malformed level string item `%s'",
                                  s->pattern));
          gnu_free(s->pattern);
          gnu_free(s);
        }
      *sep = '\0';
      sep++;

      s->level = atoi(sep);

      /* Link it to our list of debug modules. */
      s->next = debug_specs;
      debug_specs = s;
    }
  while (cp != NULL);
}


void
gnu_debug(char *fmt, ...)
{
  size_t len, size;
  va_list ap;

  if (current_function)
    snprintf(debug_buf, sizeof(debug_buf), "%s:%d:%s: ",
             current_file, current_line, current_function);
  else
    snprintf(debug_buf, sizeof(debug_buf), "%s:%d: ",
             current_file, current_line);

  len = strlen(debug_buf);
  size = sizeof(debug_buf) - len;

  va_start(ap, fmt);
  vsnprintf(debug_buf + len, size, fmt, ap);
  va_end(ap);

  fprintf(stderr, "%s\n", debug_buf);
}


/************************* Internal debug functions *************************/

void
gnu_debug_init_module(GnuDebugModule module)
{
  GnuDebugSpec s;

  if (module->initialized)
    return;

  /* Add the module to our list of known debug modules. */
  module->next = debug_modules;
  debug_modules = module;

  /* Set the debug level from the debug level string. */
  for (s = debug_specs; s; s = s->next)
    if (gnu_glob_match(s->pattern, module->name))
      {
        module->debug_level = s->level;
        break;
      }

  module->initialized = 1;
}


void
gnu_debug_lock()
{
}


void
gnu_debug_unlock()
{
}


void
gnu_debug_set_line(const char *file, int line)
{
  current_file = file;
  current_line = line;
}


void
gnu_debug_set_function(const char *function)
{
  current_function = function;
}
