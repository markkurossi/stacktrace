/*
 *
 * pigetopt.c
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

#include "piincludes.h"
#include "pigetopt.h"

/*********************** Parsing command line options ***********************/

int
pi_getopt(int argc, char *argv[], PiGetOptCtx ctx, PiGetOptOption options)
{
  int option;
  int i;

  /* Init the context unless it is already initialized. */
  if (ctx->program == NULL)
    {
      ctx->program = strrchr(argv[0], '/');
      if (ctx->program)
	ctx->program++;
      else
	ctx->program = argv[0];

      ctx->optind++;
      ctx->short_index = 0;
    }

  /* Is parsing of short bundled options pending? */
  if (ctx->short_index)
    {
      /* Yes it is. */
      ctx->short_index++;
      if (ctx->short_index < strlen(argv[ctx->optind]))
	{
	  /* More to come. */
	  option = argv[ctx->optind][ctx->short_index];
	  goto process_short_option;
	}

      /* Short bundled option parsed. */
      ctx->short_index = 0;
      ctx->optind++;
    }

  /* Move to the next argument. */
  if (ctx->optind >= argc)
    /* All options processed. */
    return -1;

  /* Check what kind of option this is. */
  if (argv[ctx->optind][0] == '-')
    {
      if (argv[ctx->optind][1] == '-')
	{
	  size_t len;
	  char *cp;
	  int index = -1;
	  int nfound = 0;
	  bool exact_match = false;

	  /* A long option. */
	  cp = strchr(argv[ctx->optind], '=');
	  if (cp)
	    len = cp - argv[ctx->optind] - 2;
	  else
	    len = strlen(argv[ctx->optind]) - 2;

	  if (len == 0)
	    /* String `--' found. */
	    return -1;

	  /* Lookup the long option. */
	  for (i = 0; options[i].long_option; i++)
	    if (strlen(options[i].long_option) >= len
		&& memcmp(options[i].long_option,
			  argv[ctx->optind] + 2, len) == 0)
	      {
		if (index < 0)
		  index = i;
		nfound++;

		/* Check for exact match if some long options share
		   common prefix with a full option. */
		if (strlen(options[i].long_option) == len)
		  exact_match = true;
	      }

	  if (nfound == 0)
	    {
	      /* Unknown option. */
	      fprintf(stderr, "%s: unknown option -- %s\n",
		      ctx->program, argv[ctx->optind] + 2);
	      return '?';
	    }
	  else if (nfound > 1 && !exact_match)
	    {
	      /* Ambiguous option. */
	      fprintf(stderr, "%s: ambiguous option -- %s\n",
		      ctx->program, argv[ctx->optind] + 2);
	      return '?';
	    }
	  /* Found a match.  Its index is in `index'. */
	  switch (options[index].arg_type)
	    {
	    case PI_GETOPT_NO_ARGUMENT:
	      if (cp)
		{
		  fprintf(stderr,
			  "%s: option doesn't take an argument "
			  "-- %s\n",
			  ctx->program, argv[ctx->optind] + 2);
		  return '?';
		}
	      ctx->optarg = NULL;
	      break;

	    case PI_GETOPT_REQUIRED_ARGUMENT:
	      if (cp == NULL)
		{
		  fprintf(stderr,
			  "%s: option requires an argument -- %s\n",
			  ctx->program, argv[ctx->optind] + 2);
		  return '?';
		}
	      ctx->optarg = cp + 1;
	      break;

	    case PI_GETOPT_OPTIONAL_ARGUMENT:
	      if (cp)
		ctx->optarg = cp + 1;
	      else
		ctx->optarg = NULL;
	      break;
	    }

	  ctx->optind++;
	  return options[index].short_option;
	}
      else if (argv[ctx->optind][1])
	{
	  /* A short option. */
	  ctx->short_index = 1;
	process_short_option:

	  /* Lookup the short option. */
	  for (i = 0; options[i].long_option; i++)
	    if (options[i].short_option == argv[ctx->optind][ctx->short_index])
	      break;
	  if (options[i].long_option == NULL)
	    {
	      fprintf(stderr, "%s: unknown option -- %c\n",
		      ctx->program,
		      argv[ctx->optind][ctx->short_index]);
	      return '?';
	    }

	  /* Found it.  Now check its type. */
	  switch (options[i].arg_type)
	    {
	    case PI_GETOPT_NO_ARGUMENT:
	      /* No arguments. */
	      ctx->optarg = NULL;
	      break;

	    case PI_GETOPT_REQUIRED_ARGUMENT:
	    case PI_GETOPT_OPTIONAL_ARGUMENT:
	      if (argv[ctx->optind][ctx->short_index + 1])
		{
		  /* Argument follows immediately after the option letter. */
		  ctx->optarg = argv[ctx->optind] + ctx->short_index + 1;

		  /* No bundled short index after this. */
		  ctx->short_index = 0;
		  ctx->optind++;
		}
	      else
		{
		  /* Argument is the next argument in the options
		     array. */
		  if (ctx->optind + 1 < argc)
		    {
		      ctx->optind++;
		      ctx->optarg = argv[ctx->optind];

		      /* No bundled short index after this. */
		      ctx->short_index = 0;
		      ctx->optind++;
		    }
		  else
		    {
		      if (options[i].arg_type == PI_GETOPT_REQUIRED_ARGUMENT)
			{
			  fprintf(stderr,
				  "%s: option requires an argument "
				  "-- %c\n",
				  ctx->program,
				  argv[ctx->optind][ctx->short_index]);
			  return '?';
			}
		      else
			{
			  ctx->optarg = NULL;
			}
		    }
		}
	      break;
	    }

	  return options[i].short_option;
	}
      else
	{
	  /* A plain `-'.  This end option processing */
	  return -1;
	}
    }

  /* End of options. */
  return -1;
}
