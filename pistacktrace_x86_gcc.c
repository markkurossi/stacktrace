/*
 *
 * pistacktrace_x86_gcc.c
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003-2007 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * What is this file for?
 *
 */

#include "piincludes.h"
#include "pistacktrace.h"

/************************** Types and definitions ***************************/

/* Get the value of the current frame pointer into the variable
   `fp'. */
#define PI_GET_FP(fp)                                   \
do                                                      \
  {                                                     \
    register void *_fp;                                 \
    asm volatile ("movl %%ebp, %0" : "=r" (_fp));       \
    (fp) = _fp;                                         \
  }                                                     \
while (0)

/* Check whether the frame pointer `fp' is valid. */
#define PI_VALID_FP(fp) ((fp) >= (void *) 0x10000000)

/* Get the next frame pointer from the frame pointer `fp'. */
#define PI_FP_GET_FP(fp) (*((void **) (fp)))

/* Get the program counter from the frame, pointed by the frame
   pointer `fp'. */
#define PI_FP_GET_PC(fp) (*((void **) (((unsigned char *) (fp)) + 4)))


/***************************** Public functions *****************************/

PiUInt32
pi_stack_trace_set(void **stack_trace, PiUInt32 stack_trace_depth)
{
  PiUInt32 i;
  void *fp;

  PI_GET_FP(fp);
  for (i = 0;
       PI_VALID_FP(fp) && i < stack_trace_depth;
       fp = PI_FP_GET_FP(fp), i++)
    stack_trace[i] = PI_FP_GET_PC(fp);

  return i;
}
