/*
 *
 * pifatal.c
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Reporting fatal errors.
 *
 */

#include "piincludes.h"

void
pi_fatal(const char *fmt, ...)
{
  char buf[1024];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  fprintf(stderr, "*** FATAL: %s\n", buf);
#ifdef ENABLE_DEBUG
  pi_malloc_dump_statistics();
  pi_malloc_dump_blocks();
#endif /* ENABLE_DEBUG */
  abort();
}
