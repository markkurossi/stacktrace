/*
 *
 * pigetopt.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003-2005 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Command line option parsing.
 *
 */

#ifndef PIGETOPT_H
#define PIGETOPT_H

/* Option arguments. */
typedef enum
{
  PI_GETOPT_NO_ARGUMENT,
  PI_GETOPT_REQUIRED_ARGUMENT,
  PI_GETOPT_OPTIONAL_ARGUMENT
} PiGetOptArgType;

/* Option description. */
struct PiGetOptOptionRec
{
  char *long_option;
  PiGetOptArgType arg_type;
  int short_option;
};

typedef struct PiGetOptOptionRec PiGetOptOptionStruct;
typedef struct PiGetOptOptionRec *PiGetOptOption;

/* Context for option parsing. */
struct PiGetOptCtxRec
{
  /* The name of the program. */
  char *program;

  /* Index of the next option to be processed. */
  int optind;

  /* Index of the current option (optind) when parsing short bundled
     options. */
  unsigned int short_index;

  /* Option's argument. */
  char *optarg;
};

typedef struct PiGetOptCtxRec PiGetOptCtxStruct;
typedef struct PiGetOptCtxRec *PiGetOptCtx;

/*********************** Parsing command line options ***********************/

/* Parse command line options array `argv' containing `argc' options.
   The argument `ctx' specifies context for the parsing operation.  It
   must be zeroed before the first call of the pi_getopt function.
   The argument `options' describes the known command line options.
   The function returns the `short_option' of the matching option on
   success and -1 when all options have been parsed.  If the command
   line options contain unknown options, the function returns '?' and
   prints a warning to the stderr. */
int pi_getopt(int argc, char *argv[], PiGetOptCtx ctx, PiGetOptOption options);

#endif /* not PIGETOPT_H */
