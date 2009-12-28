/*
 *
 * malloc_wrappers.c
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2005-2007 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Wrappers for system's memory allocation routines.
 *
 */

#include "piincludes.h"
#include "pimalloc.h"

#include <dlfcn.h>

/***************************** Global variables *****************************/

/* Allocation and free functions.  These point to some functions that
   are capable to allocate and release memory (malloc and free are
   nice). */
extern void *(*pi_malloc_ptr)(size_t);
extern void (*pi_free_ptr)(void *);


/********************** Bootstrap allocation routines ***********************/

static unsigned char bootstrap_heap[100 * 1024];
static size_t bootstrap_allocated = 0;

/* Align `number' to `align'.  The `number' and `align' must be
   integer numbers. */
#define PI_ALIGN(number, align) \
((((number) + ((align) - 1)) / (align)) * (align))

static void *
bootstrap_malloc(size_t size)
{
  void *ptr;

  size = PI_ALIGN(size, 8);

  fprintf(stderr, "pimalloc: bootstrap_malloc(%u)\n", size);

  if (bootstrap_allocated + size > sizeof(bootstrap_heap))
    {
      fprintf(stderr, "pimalloc: bootstrap heap out of space: size=%u\n",
	      size);
      return NULL;
    }

  ptr = bootstrap_heap + bootstrap_allocated;
  bootstrap_allocated += size;

  return ptr;
}


static void
bootstrap_free(void *ptr)
{
  fprintf(stderr, "pimalloc: bootstrap_malloc(%p)\n", ptr);
}


/************************** Interface to the libc ***************************/

static int initialized = 0;
static void *libc;

/*************** Wrapping system's memory allocation routines ***************/

static void init(void);

void *
malloc(size_t size)
{
  if (!initialized)
    init();

  return pi_malloc(size);
}


void
free(void *ptr)
{
  if (!initialized)
    init();

  if (ptr == (void *) 1)
    {
      pi_malloc_dump_statistics();
      pi_malloc_dump_blocks();
      return;
    }

  pi_free(ptr);
}


void *
realloc(void *ptr, size_t size)
{
  if (!initialized)
    init();

  return pi_realloc(ptr, 0, size);
}


void *
calloc(size_t number, size_t size)
{
  if (!initialized)
    init();

  return pi_calloc(number, size);
}


static void
init(void)
{
  initialized = 1;
  pi_malloc_ptr = bootstrap_malloc;
  pi_free_ptr = bootstrap_free;

  fprintf(stderr, "pimalloc: init...\n");

  libc = dlopen("libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
  if (libc == NULL)
    libc = dlopen("libc.so", RTLD_LAZY | RTLD_GLOBAL);
  if (libc == NULL)
    {
      perror("Could not open libc.so");
      exit(1);
    }

  pi_malloc_ptr = dlsym(libc, "malloc");
  if (pi_malloc_ptr == NULL)
    {
      perror("Could not fetch malloc");
      exit(1);
    }

  pi_free_ptr = dlsym(libc, "free");
  if (pi_free_ptr == NULL)
    {
      perror("Could not fetch free");
      exit(1);
    }

  fprintf(stderr, "pimalloc: malloc=%p[%p], free=%p[%p]\n",
	  pi_malloc_ptr, malloc, pi_free_ptr, free);

  atexit(pi_malloc_dump_blocks);
}
