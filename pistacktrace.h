/*
 *
 * pistacktrace.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * What is this file for?
 *
 */

#ifndef PISTACKTRACE_H
#define PISTACKTRACE_H

/***************************** Public functions *****************************/

/* Take a stack trace of the current call stack and store it into
   `stack_trace'.  The argument The `stack_trace_depth' tells how many
   program counter values fit into the `stack_trace' array.  The
   function returns the actual call stack depth. */
PiUInt32 pi_stack_trace_set(void **stack_trace, PiUInt32 stack_trace_depth);

#endif /* not PISTACKTRACE_H */
