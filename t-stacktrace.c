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

struct Count
{
  void *ptr;
  unsigned int count;
};

typedef struct Count Count;

static unsigned int
recursive(int level, void **stack_trace, unsigned int stack_trace_depth)
{
  if (level > 0)
    return recursive(level - 1, stack_trace, stack_trace_depth);

  return pi_stack_trace_set(stack_trace, stack_trace_depth);
}

static void
count_ptr(void *ptr, Count *counts)
{
  int i;

  for (i = 0; counts[i].ptr; i++)
    if (counts[i].ptr == ptr)
      break;

  counts[i].ptr = ptr;
  counts[i].count++;
}

int
main(int argc, char *argv[])
{
  void *stack_trace[20];
  Count counts[20] = {0};
  int level = 10;
  int depth;
  int i;

  depth = recursive(level, stack_trace, 20);

  /* Count program counter occurrences. */
  for (i = 0; i < depth; i++)
    count_ptr(stack_trace[i], counts);

  /* At least one PC must occur `level' times. */
  for (i = 0; counts[i].ptr; i++)
    if (counts[i].count >= level)
      break;
  if (!counts[i].ptr)
    {
      fprintf(stderr, "Could not find recursion PC!\n");
      exit(1);
    }

  return 0;
}
