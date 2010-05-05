/*
 *
 * pimalloc.c
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003-2010 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Memory allocation functions.
 *
 */

#include "piincludes.h"

#ifdef ENABLE_DEBUG

/*********************** Debugging memory allocations ***********************/

#include "pistacktrace.h"

#define PI_MALLOC_HEADER_MAGIC	0xfafefbfd
#define PI_MALLOC_TRAILER_MAGIC	0xc6e7a2d9

/* Get malloc header from the user-visible block */
#define PI_MALLOC_HEADER_FROM_BLOCK(_block)             \
((PiMallocDebugHeader) (((unsigned char *) (_block))    \
			- sizeof(PiMallocDebugHeaderStruct)))

/* Get user-visible block from malloc header. */
#define PI_MALLOC_BLOCK_FROM_HEADER(_hdr) ((void *) &(_hdr)[1])

/* Get malloc trailer from malloc header. */
#define PI_MALLOC_TRAILER_FROM_HEADER(_hdr)                     \
((PiMallocDebugTrailer) (((unsigned char *) (_hdr))             \
                         + sizeof(PiMallocDebugHeaderStruct)    \
                         + (_hdr)->alloc_size                   \
			 + (_hdr)->pad_length))

/* Get the stack trace from malloc header. */
#define PI_MALLOC_STACK_TRACE_FROM_HEADER(_hdr) \
((void **) (((unsigned char *) (_hdr))          \
            + sizeof(PiMallocDebugHeaderStruct) \
            + (_hdr)->alloc_size                \
            + (_hdr)->pad_length                \
	    + sizeof(PiMallocDebugTrailerStruct)))

/* Compute the padding after user data. */
#define PI_MALLOC_PAD_LENGTH(size)      \
(sizeof(PiMallocDebugTrailerStruct)     \
 - ((size) % sizeof(PiMallocDebugTrailerStruct)))

struct PiMallocDebugHeaderRec
{
  /* Allocated blocks are stored into a double linked list using these
     fields. */
  struct PiMallocDebugHeaderRec *next;
  struct PiMallocDebugHeaderRec *prev;

  /* When dumping memory leaks, blocks are stored into a hash table,
     where an approximate hash value is computed from the stack
     trace. */
  unsigned long hash;
  struct PiMallocDebugHeaderRec *hash_next;

  /* The size of the allocation request. */
  size_t alloc_size;

  /* Is this block seen. */
  unsigned int seen : 1;

  /* The padding length after the user data. */
  unsigned int pad_length : 24;

  /* Tag. */
  char tag[8];

  /* Pointer to free function. */
  void (*free_ptr)(void *);

  /* Header magic. */
  PiUInt32 magic;
};

typedef struct PiMallocDebugHeaderRec PiMallocDebugHeaderStruct;
typedef struct PiMallocDebugHeaderRec *PiMallocDebugHeader;

struct PiMallocDebugTrailerRec
{
  /* Trailer magic. */
  PiUInt32 magic;

  /* Stack trace from the allocation location.  The actual stack trace
     follows the trailer structure. */
  PiUInt32 stack_trace_depth;
};

typedef struct PiMallocDebugTrailerRec PiMallocDebugTrailerStruct;
typedef struct PiMallocDebugTrailerRec *PiMallocDebugTrailer;

/* Synchronization for list of allocated blocks. */

#if WINDOWS

#define WIN32_MEAN_AND_LEAN
#include <windows.h>

static bool initialized = false;
static CRITICAL_SECTION mutex;

static void
pi_malloc_lock(void)
{
  if (!initialized)
    {
      initialized = true;
      InitializeCriticalSection(&mutex);
    }

  EnterCriticalSection(&mutex);
}

static void
pi_malloc_unlock(void)
{
  LeaveCriticalSection(&mutex);
}

#else /* not WINDOWS */

#ifdef HAVE_LIBPTHREAD

#include <pthread.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void
pi_malloc_lock(void)
{
  pthread_mutex_lock(&mutex);
}

static void
pi_malloc_unlock(void)
{
  pthread_mutex_unlock(&mutex);
}

#else /* not HAVE_LIBPTHREAD */

static void
pi_malloc_lock(void)
{
}

static void
pi_malloc_unlock(void)
{
}

#endif /* not HAVE_LIBPTHREAD */
#endif /* not WINDOWS */

/***************************** Static variables *****************************/

/* Allocation and free functions.  These point to some functions that
   are capable to allocate and release memory (malloc and free are
   nice). */
void *(*pi_malloc_ptr)(size_t) = malloc;
void (*pi_free_ptr)(void *) = free;


/* Currently allocate memory blocks. */

static PiMallocDebugHeader pi_malloc_blocks;

static PiUInt32 pi_malloc_num_blocks;
static size_t pi_malloc_num_bytes;

static PiUInt32 pi_malloc_max_num_blocks;
static size_t pi_malloc_max_num_bytes;

/* Malloc padding. */
const static unsigned char pi_malloc_padding[] =
{
  '-', '*', ' ', 'm', 'a', 'l', 'l', 'o',
  'c', ' ', 'p', 'a', 'd', ' ', '*', '-',
};

/* Allocate `size' bytes of memory. */
void *
pi_do_allocate(size_t size)
{
  size_t pad_length, i;
  PiMallocDebugHeader hdr;
  PiMallocDebugTrailer trailer;
  void *stack_trace[100];
  PiUInt32 stack_trace_depth;
  unsigned char *data;
  void **st;

  pi_malloc_lock();

  /* Take a stack_trace. */
  stack_trace_depth = pi_stack_trace_set(stack_trace, 100);

  /* Compute the padding length. */
  pad_length = PI_MALLOC_PAD_LENGTH(size);

  /* And allocate some memory. */
  hdr = (*pi_malloc_ptr)(sizeof(PiMallocDebugHeaderStruct)
			 + size + pad_length
			 + sizeof(PiMallocDebugTrailerStruct)
			 + stack_trace_depth * sizeof(void *));
  if (hdr == NULL)
    {
      pi_malloc_unlock();
      return NULL;
    }

  /* Update information about allocated memory blocks. */

  hdr->next = pi_malloc_blocks;
  if (hdr->next)
    hdr->next->prev = hdr;
  hdr->prev = NULL;

  pi_malloc_blocks = hdr;

  pi_malloc_num_blocks++;
  if (pi_malloc_num_blocks > pi_malloc_max_num_blocks)
    pi_malloc_max_num_blocks = pi_malloc_num_blocks;

  pi_malloc_num_bytes += size;
  if (pi_malloc_num_bytes > pi_malloc_max_num_bytes)
    pi_malloc_max_num_bytes = pi_malloc_num_bytes;

  /* Prepare the header. */
  hdr->alloc_size = size;
  hdr->seen = 0;
  hdr->pad_length = pad_length;
  memset(hdr->tag, 0, sizeof(hdr->tag));
  hdr->free_ptr = pi_free_ptr;
  hdr->magic = PI_MALLOC_HEADER_MAGIC;

  /* Padding. */
  data = PI_MALLOC_BLOCK_FROM_HEADER(hdr);
  for (i = 0; i < pad_length; i++)
    data[size + i] = pi_malloc_padding[i % sizeof(pi_malloc_padding)];

  /* Trailer. */
  trailer = PI_MALLOC_TRAILER_FROM_HEADER(hdr);
  trailer->magic = PI_MALLOC_TRAILER_MAGIC;
  trailer->stack_trace_depth = stack_trace_depth;

  /* Stack trace. */

  st = PI_MALLOC_STACK_TRACE_FROM_HEADER(hdr);
  memcpy(st, stack_trace, stack_trace_depth * sizeof(void *));

  hdr->hash = 0;

  for (i = 0; i < stack_trace_depth; i++)
    hdr->hash ^= ((unsigned long) stack_trace[i]) >> 2;

  pi_malloc_unlock();

  /* Return the user block. */
  return PI_MALLOC_BLOCK_FROM_HEADER(hdr);
}


void
pi_do_free(void *ptr)
{
  PiMallocDebugHeader hdr;
  PiMallocDebugTrailer tr;
  size_t i;
  unsigned char *data;

  pi_malloc_lock();

  /* Check header. */

  hdr = PI_MALLOC_HEADER_FROM_BLOCK(ptr);

  if (hdr->magic != PI_MALLOC_HEADER_MAGIC)
    pi_fatal("Freeing a block with invalid header magic");

  /* Check padding. */
  data = ((unsigned char *) ptr) + hdr->alloc_size;
  for (i = 0; i < hdr->pad_length; i++)
    if (data[i] != pi_malloc_padding[i % sizeof(pi_malloc_padding)])
      pi_fatal("Freeing a block whose trailer padding is corrupted");

  /* Check trailer. */

  tr = PI_MALLOC_TRAILER_FROM_HEADER(hdr);

  if (tr->magic != PI_MALLOC_TRAILER_MAGIC)
    pi_fatal("Freeing a block with invalid trailer magic");

  /* Everything ok. */

  /* Update statistics. */
  pi_malloc_num_blocks--;
  pi_malloc_num_bytes -= hdr->alloc_size;

  /* Let's invalidate the magics and free the block. */

  hdr->magic = 0;
  tr->magic = 0;

  if (hdr->next)
    hdr->next->prev = hdr->prev;
  if (hdr->prev)
    hdr->prev->next = hdr->next;
  else
    pi_malloc_blocks = hdr->next;

  (*hdr->free_ptr)(hdr);

  pi_malloc_unlock();
}


void *
pi_malloc(size_t size)
{
  return pi_do_allocate(size);
}


void *
pi_calloc(size_t number, size_t size)
{
  unsigned char *data;
  size_t len = number * size;

  PI_ASSERT(len != 0);

  data = pi_do_allocate(len);
  if (data)
    memset(data, 0, len);

  return data;
}


void *
pi_realloc(void *ptr, size_t old_size, size_t new_size)
{
  PiMallocDebugHeader hdr;
  unsigned char *data;
  size_t i;

  PI_ASSERT(new_size != 0);

  if (ptr == NULL)
    {
      PI_ASSERT(old_size == 0);
      return pi_do_allocate(new_size);
    }

  hdr = PI_MALLOC_HEADER_FROM_BLOCK(ptr);

  if (old_size && hdr->alloc_size != old_size)
    pi_fatal("Reallocating block with wrong idea about old size");

  if (hdr->alloc_size < new_size)
    {
      /* Making the block bigger.  Just allocate a fresh block. */
      data = pi_do_allocate(new_size);
      if (data)
	/* Preserve old data. */
	memcpy(data, ptr, hdr->alloc_size);

      /* Free the old block. */
      pi_do_free(ptr);

      return data;
    }

  /* Making the block smaller.  Just fill the padding and we are
     done. */

  hdr->pad_length += hdr->alloc_size - new_size;
  hdr->alloc_size = new_size;

  pi_malloc_num_bytes -= hdr->alloc_size - new_size;

  data = (unsigned char *) ptr;
  for (i = 0; i < hdr->pad_length; i++)
    data[new_size + i] = pi_malloc_padding[i % sizeof(pi_malloc_padding)];

  /* Return the old block. */
  return ptr;
}


void
pi_free(void *ptr)
{
  if (ptr)
    pi_do_free(ptr);
}


char *
pi_strdup(const char *str)
{
  char *data;

  PI_ASSERT(str);
  data = pi_do_allocate(strlen(str) + 1);
  if (data)
    strcpy(data, str);

  return data;
}


unsigned char *
pi_memdup(const unsigned char *data, size_t len)
{
  unsigned char *ptr;

  ptr = pi_do_allocate(len + 1);
  if (ptr)
    {
      memcpy(ptr, data, len);
      ptr[len] = '\0';
    }

  return ptr;
}


void
pi_malloc_tag_block(void *ptr, const char *tag)
{
  PiMallocDebugHeader hdr;
  size_t i;

  if (ptr == NULL)
    return;

  hdr = PI_MALLOC_HEADER_FROM_BLOCK(ptr);

  if (hdr->magic != PI_MALLOC_HEADER_MAGIC)
    /* Invalid magic.  This could indicate a corrupted block, or
       simply the fact that the blocks is not mallocated() but it is
       inlined inside another block. */
    return;

  /* Clear old tag. */
  memset(hdr->tag, 0, sizeof(hdr->tag));

  if (tag == NULL)
    return;

  for (i = 0; i < sizeof(hdr->tag) - 1 && tag[i]; i++)
    hdr->tag[i] = tag[i];
}


/* Dump additional symbol files that are in use in this
   application. */
static void
pi_malloc_dump_symbol_files(FILE *outfp)
{
#ifdef __linux__
  pid_t pid = getpid();
  char buf[2048];
  char exe[1024];
  int i;
  FILE *fp;
  char *cp;

  /* Resole the executable name. */

  snprintf(buf, sizeof(buf), "/proc/%u/exe", pid);
  i = readlink(buf, exe, sizeof(exe) - 1);
  if (i < 0)
    {
      /* Could not read symlink. */
      fprintf(stderr,
	      "pi_malloc_dump_symbol_files(): could not readlink(%s): %s\n",
	      buf, strerror(errno));
      return;
    }
  exe[i] = '\0';

  /* Read maps. */

  snprintf(buf, sizeof(buf), "/proc/%u/maps", pid);
  fp = fopen(buf, "r");
  if (fp == NULL)
    {
      /* Could not read maps. */
      fprintf(stderr,
	      "pi_malloc_dump_symbol_files(): could not fopen(%s): %s\n",
	      buf, strerror(errno));
      return;
    }

  while (fgets(buf, sizeof(buf), fp))
    {
      unsigned long int addr;
      unsigned long int size;

      /* Delete trailing whitespace. */
      i = strlen(buf);
      for (i--;
	   i >= 0 && (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t');
	   i--)
	;
      i++;
      buf[i] = '\0';

      /* Get address. */
      addr = strtoul(buf, &cp, 16);
      if (*cp != '-')
	/* Malformed line. */
	continue;

      /* Compute section's size from the end offset. */
      cp++;
      size = strtoul(cp, &cp, 16);
      if (*cp != ' ')
	/* Malformed line. */
	continue;

      size -= addr;
      cp++;

      /* Check mode column. */
      if (cp[0] == ' ' || cp[1] == ' ' || cp[2] == ' ' || cp[3] == ' '
	  || cp[4] != ' ')
	/* No mode column found. */
	continue;

      if (cp[1] == 'w')
	/* The map is writable.  Skip this map. */
	continue;

      cp += 5;

      /* Skip file offset. */
      cp = strchr(cp, ' ');
      if (cp == NULL)
	/* Malformed line. */
	continue;

      /* Skip device major & minor. */
      cp++;
      cp = strchr(cp, ' ');
      if (cp == NULL)
	/* Malformed line. */
	continue;

      /* Skip inode. */
      for (cp++; *cp && '0' <= *cp && *cp <= '9'; cp++)
	;

      /* Skip whitespace. */
      for (; *cp && (*cp == ' ' || *cp == '\t' || *cp == '\n'); cp++)
	;

      if (*cp == '\0')
	/* No shared object of file path name specified. */
	continue;

      /* Found a new symbol file. */
      fprintf(outfp,
	      "<symbol-file offset=\"%lx\" size=\"%lx\" file=\"%s\"/>\n",
	      addr, size, cp);
    }
  fclose(fp);

#endif /* __linux__ */
}


void
pi_malloc_dump_blocks(void)
{
  PiMallocDebugHeader h, h2;
  PiMallocDebugTrailer t, t2;
  void **st, **st2;
  char *leak_file_name = "stacktrace.log";
  FILE *ofp;
  char *where;
  size_t i, idx;
  PiUInt32 num_leaks = 0;
  size_t total_bytes = 0;
  PiMallocDebugHeader *hash;
  size_t hash_size = 10240;

  pi_malloc_lock();

  if (pi_malloc_blocks == NULL)
    {
      pi_malloc_unlock();
      fprintf(stderr, "malloc: no memory leaks\n");
      return;
    }

  /* Open output file. */
  ofp = fopen(leak_file_name, "wb");
  if (ofp == NULL)
    ofp = stderr;

  /* Dump additional symbol files that are in use in this program. */
  pi_malloc_dump_symbol_files(ofp);

  /* Insert all blocks to the hash table. */

  hash = (*pi_malloc_ptr)(hash_size * sizeof(*hash));
  if (hash == NULL)
    {
      pi_malloc_unlock();
      fprintf(stderr, "malloc: could not allocate block hash\n");
      return;
    }

  memset(hash, 0, hash_size * sizeof(*hash));

  for (h = pi_malloc_blocks; h; h = h->next)
    {
      idx = h->hash % hash_size;

      h->hash_next = hash[idx];
      hash[idx] = h;
    }

  /* Dump all blocks. */
  for (idx = 0; idx < hash_size; idx++)
    for (h = hash[idx]; h; h = h->hash_next)
      {
        size_t bytes = 0;
        size_t blocks = 0;
        unsigned char *data;
        size_t data_len;

        if (h->seen)
          /* This block is already seen. */
          continue;

        bytes = h->alloc_size;
        blocks = 1;

        /* Check if there are any similar blocks to this one. */

        t = PI_MALLOC_TRAILER_FROM_HEADER(h);
        st = PI_MALLOC_STACK_TRACE_FROM_HEADER(h);

        for (h2 = h->hash_next; h2; h2 = h2->hash_next)
          {
            if (h2->seen)
              /* This is already seen. */
              continue;

            t2 = PI_MALLOC_TRAILER_FROM_HEADER(h2);
            st2 = PI_MALLOC_STACK_TRACE_FROM_HEADER(h2);

            if (t->stack_trace_depth == t2->stack_trace_depth
                && memcmp(st, st2, t->stack_trace_depth * sizeof(void *)) == 0
                && memcmp(h->tag, h2->tag, sizeof(h->tag)) == 0)
              {
                /* This matches. */
                h2->seen = 1;

                bytes += h2->alloc_size;
                blocks++;
              }
          }

        /* Update global statistics. */
        num_leaks++;
        total_bytes += bytes;

        /* Header. */
        fprintf(ofp, "<stacktrace blocks=\"%u\" bytes=\"%u\" data=\"",
                blocks, bytes);

        /* Start of block's data. */

        data_len = 256;
        if (data_len > h->alloc_size)
          data_len = h->alloc_size;

        data = PI_MALLOC_BLOCK_FROM_HEADER(h);

        for (i = 0; i < data_len; i++)
          fprintf(ofp, "%02x", data[i]);

        fprintf(ofp, "\"");

        if (h->tag[0])
          fprintf(ofp, " tag=\"%s\"", h->tag);

        fprintf(ofp, ">\n");

        /* Stack trace. */
        for (i = 0; i < t->stack_trace_depth; i++)
          fprintf(ofp, "  <pc>%p</pc>\n", st[i]);
        fprintf(ofp, "</stacktrace>\n");
      }

  /* Clear seen flags. */
  for (h = pi_malloc_blocks; h; h = h->next)
    h->seen = 0;

  /* Free hash table. */
  (*pi_free_ptr)(hash);

  /* Close output file if it was opened. */
  if (ofp == stderr)
    {
      where = "stderr";
    }
  else
    {
      where = leak_file_name;
      fclose(ofp);
    }

  if (num_leaks)
    {
      fprintf(stderr,
	      "\
**********************************************************************\n\
*\n\
*       Memory leaks found: %u leak%s, %u bytes\n\
*       Memory leaks dumped to `%s'\n\
*\n\
**********************************************************************\n",
	      num_leaks, num_leaks > 1 ? "s" : "", total_bytes, where);
    }
  else
    {
      fprintf(stderr, "No memory leaks.");
    }

  pi_malloc_unlock();
}


void
pi_malloc_dump_statistics(void)
{
  pi_malloc_lock();

  fprintf(stderr,
	  "malloc: now: #blocks=%u, #bytes=%u max: #blocks=%u, #bytes=%u\n",
	  pi_malloc_num_blocks, pi_malloc_num_bytes,
	  pi_malloc_max_num_blocks, pi_malloc_max_num_bytes);

  pi_malloc_unlock();
}


#else /* not ENABLE_DEBUG */

void *
pi_malloc(size_t size)
{
  PI_ASSERT(size != 0);
  return malloc(size);
}


void *
pi_calloc(size_t number, size_t size)
{
  PI_ASSERT(number * size != 0);
  return calloc(number, size);
}


void *
pi_realloc(void *ptr, size_t old_size, size_t new_size)
{
  PI_ASSERT(new_size != 0);

  if (ptr == NULL)
    return malloc(new_size);

  return realloc(ptr, new_size);
}


void
pi_free(void *ptr)
{
  if (ptr)
    free(ptr);
}


char *
pi_strdup(const char *str)
{
  PI_ASSERT(str);
  return strdup(str);
}


unsigned char *
pi_memdup(const unsigned char *data, size_t len)
{
  unsigned char *ptr;

  ptr = pi_malloc(len + 1);
  if (ptr)
    {
      memcpy(ptr, data, len);
      ptr[len] = '\0';
    }

  return ptr;
}

#endif /* not ENABLE_DEBUG */
