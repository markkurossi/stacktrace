/*
 *
 * pimalloc.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003-2007 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Memory allocation functions.
 *
 */

#ifndef PIMALLOC_H
#define PIMALLOC_H

/* Allocate `size' bytes of memory.  The function returns a pointer to
   the beginning of the allocated memory block or NULL if the system
   ran out of memory. */
void *pi_malloc(size_t size);

/* XXX */
void *pi_calloc(size_t number, size_t size);

/* XXX */
void *pi_realloc(void *ptr, size_t old_size, size_t new_size);

/* XXX */
void pi_free(void *ptr);

/* XXX */
char *pi_strdup(const char *str);

/* XXX */
unsigned char *pi_memdup(const unsigned char *data, size_t len);

/* Tag block `ptr' with the tag `tag'.  The maximum length of the tag
   is 7 characters. */
void pi_malloc_tag_block(void *ptr, const char *tag);

/* XXX */
void *pi_xmalloc(size_t size);

/* XXX */
void *pi_xcalloc(size_t number, size_t size);

/* XXX */
void *pi_xrealloc(void *ptr, size_t old_size, size_t new_size);

/* XXX */
void pi_xfree(void *ptr);

/* XXX */
char *pi_xstrdup(const char *str);

/* XXX */
unsigned char *pi_xmemdup(const unsigned char *data, size_t len);

#ifdef ENABLE_DEBUG

/* Memory leak debugging. */

/* XXX */
void pi_malloc_dump_blocks(void);

/* XXX */
void pi_malloc_dump_statistics(void);

#endif /* ENABLE_DEBUG */

#endif /* PIMALLOC_H */
