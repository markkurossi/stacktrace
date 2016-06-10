/*
 *
 * t-stacktrace.c
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2016 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Unit tests for stacktrace.
 *
 */

#include "piincludes.h"
#include "pistacktrace.h"

static unsigned int
recursive(int level, void **stack_trace, unsigned int stack_trace_depth)
{
  if (level > 0)
    return recursive(level - 1, stack_trace, stack_trace_depth);

  return pi_stack_trace_set(stack_trace, stack_trace_depth);
}

int
main(int argc, char *argv[])
{
  void *stack_trace[20];
  int depth;
  int i;

  depth = recursive(10, stack_trace, 20);
  for (i = depth - 1; i >= 0; i--)
    fprintf(stdout, "\t%p\n", stack_trace[i]);

  return 0;
}
