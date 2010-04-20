/*
 * stacktrace.c
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2001-2010 Markku Rossi.
 *
 * Map program counter values for source files.  The program
 * implements both an interactive memory leak check shell and a
 * batch-mode leak dump annotator.
 *
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gnuincludes.h"
#include "gnuglob.h"

#include "pigetopt.h"
#include <assert.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_BFD_H
#include <bfd.h>
#define HAVE_SYMBOL_FILE 1
#endif /* HAVE_BFD_H */


/************************** Types and definitions ***************************/

/* Check if the character `ch' is a valid hexadecimal character. */
#define IS_HEX(ch)                      \
  (('0' <= (ch) && (ch) <= '9')         \
   || ('a' <= (ch) && (ch) <= 'f')      \
   || ('A' <= (ch) && (ch) <= 'F'))

#define HEX_TO_INT(ch)                  \
(('0' <= (ch) && (ch) <= '9')           \
 ? (ch) - '0'                           \
 : (('a' <= (ch) && (ch) <= 'f')        \
    ? (ch) - 'a' + 10                   \
    : (('A' <= (ch) && (ch) <= 'F')     \
       ? (ch) - 'A' + 10                \
       : 0)))

/* Check if the character `ch' is a whitespace character. */
#define ISSPACE(ch) ((ch) == ' ' || (ch) == '\n' || (ch) == '\t')

/* The section from which the PC values are relocated. */
#define SECTION_NAME ".text"

/* The name of the init file. */
#define INIT_FILE_NAME ".stacktraceinit"

/* Leak types. */
typedef enum
{
  LEAK_MEM,
  LEAK_GROUP,
  LEAK_FD
} LeakType;

/* Leak grouping types. */
typedef enum
{
  GROUP_BY_FILE,
  GROUP_BY_FUNCTION,
  GROUP_BY_LEAK
} LeakGroupType;

/* A stack frame. */
struct StackFrameRec
{
  /* Flags. */
  unsigned int leaf : 1;        /* A leaf leak.  Do not proceed any deeper. */

  /* Information about the frame. */
  unsigned long pc;
  const char *filename;
  const char *functionname;
  int line;
};

typedef struct StackFrameRec StackFrameStruct;
typedef struct StackFrameRec *StackFrame;

/* Memory leak with the stack frame of the allocation location. */
struct MemoryLeakRec
{
  struct MemoryLeakRec *next;
  struct MemoryLeakRec *prev;

  /* Flags. */
  unsigned int dynamic_label : 1; /* Dynamic label. */
  unsigned int type : 2;          /* LEAK_MEM, LEAK_GROUP, or LEAK_FD. */
  unsigned int hidden : 1;        /* Hidden. */
  unsigned int marked : 1;        /* Marked for operation. */
  unsigned int has_seqnum : 1;	  /* Leak has alloc sequence number. */
  unsigned int fd_is_open : 1;    /* FD is open. */

  /* Group type. */
  unsigned int group_type : 2;

  char *filename;
  unsigned int line;

  char *tag;
  char *type_name;

  unsigned int blocks;
  unsigned int bytes;
  unsigned int seqnum;

  /* Data from the beginning of the leaked block. */
  unsigned char *data;
  size_t data_len;

  /* File descriptor info. */
  unsigned long fd;
  char *fd_type;

  unsigned int num_stack_frames;
  StackFrame stack_frames;

  /* Close stack frame for file descriptors. */
  unsigned int num_close_stack_frames;
  StackFrame close_stack_frames;


  struct MemoryLeakRec *grouped;
};

typedef struct MemoryLeakRec MemoryLeakStruct;
typedef struct MemoryLeakRec *MemoryLeak;

/* A leaf node specification. */
struct LeafNodeRec
{
  struct LeafNodeRec *next;

  /* An unique index for this leaf specification. */
  unsigned int index;

  /* Flags. */
  unsigned int disabled : 1;    /* Leaf disabled. */

  /* How many frames this selector matches. */
  unsigned int num_matches;

  /* Leaf specification.  Either or both of these can be defined. */
  char *functionname;
  char *filename;
};

typedef struct LeafNodeRec LeafNodeStruct;
typedef struct LeafNodeRec *LeafNode;

#if HAVE_SYMBOL_FILE

/* PC hash table entry. */
struct PCHashEntryRec
{
  struct PCHashEntryRec *next;

  unsigned long pc;
  const char *filename;
  const char *functionname;
  int line;
};

typedef struct PCHashEntryRec PCHashEntryStruct;
typedef struct PCHashEntryRec *PCHashEntry;

/* A symbol file. */
struct SymbolFileRec
{
  /* Link field for symbol files. */
  struct SymbolFileRec *next;

  /* The file path name. */
  char *symbol_file;

  /* Section from which the PC values are relocated.  This is the
     contents of the section SECTION_NAME. */
  asection *sect;

  /* Offset of text file of this symbol file and its size. */
  unsigned long offset;
  size_t size;

  /* Binary file descriptor for the symbol file. */
  bfd *abfd;

  /* Symbols from the file. */
  long num_syms;
  asymbol **syms;
};

typedef struct SymbolFileRec SymbolFileStruct;
typedef struct SymbolFileRec *SymbolFile;

#endif /* HAVE_SYMBOL_FILE */


/***************************** Static variables *****************************/

/* The version of this program. */
static char *version_string = "stacktrace 0.9.3";

/* The name of this program. */
static PiGetOptCtxStruct optctx;

/* The name of the executable. */
static char *exe = NULL;

#if HAVE_SYMBOL_FILE
/* The size of the PC hash table. */
#define PC_HASH_SIZE 8192

/* PC hash table. */
static PCHashEntry pc_hash[PC_HASH_SIZE];

/* The loaded symbol files. */
SymbolFile symbol_files_head = NULL;
SymbolFile symbol_files_tail = NULL;
#endif /* HAVE_SYMBOL_FILE */

/* The PC signatures in the dump formats. */
static const struct
{
  char *prefix;
  GnuBool attributes;
} signatures[] =
{
  {"\tpc=0x",		FALSE},
  {"<pc>0x",		FALSE},
  {"  <pc>0x",		FALSE},
  {"  <pc ",		TRUE},
  {"    <pc>0x",	FALSE},
  {"    <pc ",		TRUE},

  {NULL, FALSE},
};

/* Print full source file names or just the base names. */
static int fullname = 0;

/* Enable additional symbol files automatically. */
static int enable_symbol_files = 0;

/* The input file to use. */
static FILE *ifp = NULL;

/* The output file for batch mode. */
static FILE *ofp = NULL;

/* Run in batch mode. */
static int batch = 0;

/* Read leakdump from stdin. */
static int stdin_leakdump = 0;

/* Read commands from the init file. */
static int read_init_file = 1;

/* Verbosity level. */
static int verbose = 0;

/* Root directory. */
static char *root_dir = NULL;

/* Memory leaks. */
static MemoryLeak leaks = NULL;
static MemoryLeak leaks_tail = NULL;
unsigned int num_leaks = 0;
unsigned long num_leak_blocks = 0;
unsigned long num_leak_frames = 0;
unsigned long num_leak_bytes = 0;

/* The current memory leak. */
static MemoryLeak current_leak = NULL;
static unsigned int current_leak_index = 0;
unsigned int current_frame = 0;

/* Leaf nodes. */
static LeafNode leaf_nodes_head = NULL;
static LeafNode leaf_nodes_tail = NULL;
static unsigned int next_leaf_index = 1;

static void *last_command = NULL;

/* Command line options. */
static PiGetOptOptionStruct longopts[] =
{
  {"batch",             	PI_GETOPT_NO_ARGUMENT,  	  'b'},
  {"enable-symbol-files",	PI_GETOPT_NO_ARGUMENT,            'e'},
  {"fullname",          	PI_GETOPT_NO_ARGUMENT,            'f'},
  {"help",              	PI_GETOPT_NO_ARGUMENT,            'h'},
  {"output",            	PI_GETOPT_REQUIRED_ARGUMENT,      'o'},
  {"verbose",           	PI_GETOPT_NO_ARGUMENT,            'v'},
  {"version",           	PI_GETOPT_NO_ARGUMENT,            'V'},
  {"stdin",             	PI_GETOPT_NO_ARGUMENT,            's'},
  {"nx",                	PI_GETOPT_NO_ARGUMENT,            'n'},
  {NULL, 0, 0},
};

#if HAVE_SYMBOL_FILE
/*************************** Symbol file options ****************************/

/* Add a symbol file `symbol_file' whose text section's offset is
   `offset' and size `size'.  The function returns TRUE if the
   operation was successful and FALSE otherwise. */
static GnuBool add_symbol_file(const char *symbol_file, unsigned long offset,
			       size_t size);

/* Enable the symbol file `symbol_file'.  The symbol file must have
   been added first with the add_symbol_file() function. */
static GnuBool enable_symbol_file(const char *symbol_file);

/* Find the nearest line for the PC `pc' from the loaded symbol files.
   The function returns TRUE if the PC value `pc' could be resolved or
   FALSE otherwise. */
static GnuBool find_nearest_line(unsigned long pc,
                                 const char **file, const char **func,
                                 int *line);
#endif /* HAVE_SYMBOL_FILE */


/******************* Prototypes for static help functions *******************/

/* Print short usage information. */
static void usage(void);

/* Print the program version information. */
static void version(void);

/* Report a message. */
static void message(char *fmt, ...);

/* Read in a memory leak dump file. */
static void read_dump_file(void);

/* Implement the actual `help' command of the interactive shell. */
static void do_cmd_help(void);

/* Print detailed help about command `cmd'.  This is called from the
   interactive shell's `help' command. */
static void do_help_on_cmd(char *cmd);

/* Find the command `name' from the list of known commands.  The
   function returns -2 if the argument `name' is an ambiguous prefix,
   -1 if the command was not found, and the command's index
   otherwise. */
static int find_command(char *name);

/* The interactive memory leak check shell. */
static void memory_leak_check_shell(void);

/* Print global information about memory leaks. */
static void global_leak_info(void);

/* Read init file either from the current working directory, or if
   that is not specified, from the user's home directory. */
static void do_read_init_file(void);


/***************************** Global functions *****************************/

int
main(int argc, char *argv[])
{
  int ch;

  /* Init some options for their default values. */
  ofp = stdout;

  /* Parse options. */
  while ((ch = pi_getopt(argc, argv, &optctx, longopts)) != -1)
    {
      switch (ch)
        {
        case 'b':
          batch = 1;
          break;

	case 'e':
	  enable_symbol_files = 1;
	  break;

        case 'f':
          fullname = 1;
          break;

        case 'h':
          usage();
          exit(0);
          break;

        case 'n':
          read_init_file = 0;
          break;

        case 'o':
          ofp = fopen(optctx.optarg, "w");
          if (ofp == NULL)
            {
              fprintf(stderr, "%s: could not create output file `%s': %s\n",
                      optctx.program, optctx.optarg, strerror(errno));
              exit(1);
            }
          break;

        case 'v':
          verbose++;
          break;

        case 'V':
          version();
          exit(0);
          break;

        case 's':
          stdin_leakdump = 1;
          break;

        case '0':
          /* Long only option. */
          break;

        case '?':
          fprintf(stderr, "Try `%s --help' for more information.\n",
                  optctx.program);
          exit(1);
          break;

        default:
          usage();
          exit(1);
          break;
        }
    }
#if HAVE_SYMBOL_FILE
  if (optctx.optind + 1 > argc || optctx.optind + 2 < argc)
    {
      usage();
      exit(1);
    }
#else /* not HAVE_SYMBOL_FILE */
  if (optctx.optind > argc || optctx.optind + 1 < argc)
    {
      usage();
      exit(1);
    }
#endif /* not HAVE_SYMBOL_FILE */

  if (stdin_leakdump == 1 && batch == 0)
    {
      usage();
      exit(1);
    }

#if HAVE_SYMBOL_FILE
  if (optctx.optind < argc)
    {
      exe = argv[optctx.optind];
      optctx.optind++;
    }
#else /* not HAVE_SYMBOL_FILE */
  exe = "stacktrace";
#endif /* not HAVE_SYMBOL_FILE */

  if (stdin_leakdump == 1)
    {
      ifp = stdin;
    }
  else
    {
      if (optctx.optind < argc)
        {
          ifp = fopen(argv[optctx.optind], "r");
          if (ifp == NULL)
            {
              fprintf(stderr, "%s: could not open dump file `%s': %s\n",
                      optctx.program, argv[optctx.optind], strerror(errno));
              exit(1);
            }
          optctx.optind++;
        }
    }

#if HAVE_SYMBOL_FILE
  bfd_init();

  /* Add the program as the default symbol file. */
  if (!add_symbol_file(exe, 0, 0)
      || !enable_symbol_file(exe))
    exit(1);
#endif /* HAVE_SYMBOL_FILE */

  /* Read the dump file if needed. */
  if (ifp)
    {
      if (verbose)
        message("Reading dump file.\n");
      read_dump_file();
      fclose(ifp);
    }

  /* Read init file unless it is not allowed by command line
     option. */
  if (read_init_file)
    do_read_init_file();

  if (batch)
    {
      fclose(ofp);
    }
  else
    {
      /* Run as interactive memory leak check shell. */
      memory_leak_check_shell();
    }

  return 0;
}


/***************************** Interned strings *****************************/

struct StringRegRec
{
  struct StringRegRec *next;
  char *data;
  size_t len;
};

typedef struct StringRegRec StringRegStruct;
typedef struct StringRegRec *StringReg;

#define HASH_SIZE 8192

static unsigned int
count_hash(const char *string, size_t len)
{
  unsigned int val = 0;
  unsigned char *data = (unsigned char *) string;
  size_t i;

  for (i = 0; i < len; i++)
    val = (val << 5) ^ data[i] ^ (val >> 16) ^ (val >> 7);

  return val % HASH_SIZE;
}


static char *
intern(const char *string, size_t len)
{
  static StringReg table[8192] = {0};
  unsigned int hash;
  StringReg reg;

  if (string == NULL)
    return NULL;

  if (len == 0)
    len = strlen(string);

  hash = count_hash(string, len);

  /* Do we know this? */
  for (reg = table[hash]; reg; reg = reg->next)
    if (reg->len == len && memcmp(string, reg->data, len) == 0)
      /* Found it. */
      return reg->data;

  /* Create a new entry. */

  reg = gnu_xcalloc(1, sizeof(*reg));

  reg->data = gnu_xmalloc(len + 1);
  memcpy(reg->data, string, len);
  reg->data[len] = '\0';
  reg->len = len;

  reg->next = table[hash];
  table[hash] = reg;

  return reg->data;
}


#if HAVE_SYMBOL_FILE

/****************************** PC hash table *******************************/

/* Lookup program counter value `pc' from the hash table.  Returns the
   cached entry or NULL if the entry is unknown. */
static PCHashEntry
pc_hash_lookup(unsigned long pc)
{
  int hash = pc % PC_HASH_SIZE;
  PCHashEntry entry;

  for (entry = pc_hash[hash]; entry; entry = entry->next)
    if (entry->pc == pc)
      return entry;

  return NULL;
}

/* Add program counter value `pc' to the PC hash table.  The arguments
   `file', `func', `line' contain information about the PC value.  The
   function returns the added hash entry. */
static PCHashEntry
pc_hash_add(unsigned long pc, const char *file, const char *func, int line)
{
  int hash = pc % PC_HASH_SIZE;
  PCHashEntry entry;

  entry = gnu_calloc(1, sizeof(*entry));

  entry->pc = pc;
  if (file)
    entry->filename = intern(file, strlen(file));
  if (func)
    entry->functionname = intern(func, strlen(func));
  entry->line = line;

  entry->next = pc_hash[hash];
  pc_hash[hash] = entry;

  return entry;
}


/* Clear PC hash table. */
static void
pc_hash_clear()
{
  int i;

  for (i = 0; i < PC_HASH_SIZE; i++)
    while (pc_hash[i])
      {
        PCHashEntry entry = pc_hash[i];
        pc_hash[i] = entry->next;

        gnu_free(entry);
      }
}

/************************** Symbol file operations **************************/

static asymbol **
slurp_symtabl(bfd *abfd, long *symcount)
{
  asymbol **sy = NULL;
  long storage;

  if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
    {
      fprintf(stderr, "%s: no symbols in `%s'\n",
              optctx.program, bfd_get_filename(abfd));
      return NULL;
    }

  storage = bfd_get_symtab_upper_bound(abfd);
  if (storage < 0)
    {
      fprintf(stderr, "%s: fatal\n", bfd_get_filename(abfd));
      exit(1);
    }

  if (storage)
    {
      sy = (asymbol **) malloc (storage);
    }
  *symcount = bfd_canonicalize_symtab(abfd, sy);
  if (*symcount < 0)
    {
      fprintf(stderr, "%s: fatal\n", bfd_get_filename(abfd));
      exit(1);
    }
  if (*symcount == 0)
    fprintf(stderr, "%s: %s: No symbols\n",
            optctx.program, bfd_get_filename (abfd));
  return sy;
}


static GnuBool
add_symbol_file(const char *symbol_file, unsigned long offset, size_t size)
{
  SymbolFile file;

  /* Link the new symbol file into our list of symbol files. */
  file = gnu_xcalloc(1, sizeof(*file));
  file->symbol_file = gnu_xstrdup(symbol_file);
  file->offset = offset;
  file->size = size;

  if (symbol_files_tail)
    symbol_files_tail->next = file;
  else
    symbol_files_head = file;

  symbol_files_tail = file;

  return TRUE;
}


static GnuBool
enable_symbol_file(const char *symbol_file)
{
  bfd *abfd;
  char **matching;
  long symcount;
  asymbol **syms;
  asection *sect;
  SymbolFile file;

  /* Lookup the file. */
  for (file = symbol_files_head; file; file = file->next)
    if (strcmp(file->symbol_file, symbol_file) == 0)
      break;
  if (file == NULL)
    /* An unknown symbol file. */
    return FALSE;

  if (file->abfd)
    /* Already enabled. */
    return TRUE;

  abfd = bfd_openr(symbol_file, NULL);
  if (abfd == NULL)
    {
      fprintf(stderr, "%s: could not open symbol file `%s': %s\n",
              optctx.program, symbol_file, bfd_errmsg(bfd_get_error()));
      return FALSE;
    }

  if (!bfd_check_format_matches(abfd, bfd_object, &matching))
    {
      fprintf(stderr, "%s: %s: format mismatch: %s\n", optctx.program,
              symbol_file, bfd_errmsg(bfd_get_error()));
      if (bfd_get_error() == bfd_error_file_ambiguously_recognized)
        {
          char **p = matching;

          fprintf(stderr, "%s: %s: matching formats:",
                  optctx.program, symbol_file);
          while (*p)
            fprintf(stderr, " %s", *p++);
          fprintf(stderr, "\n");

          free(matching);
        }

      (void) bfd_close(abfd);
      return FALSE;
    }

  printf("%s: %s: file format %s\n",
         optctx.program, bfd_get_filename(abfd), abfd->xvec->name);

  /* Fetch symbols. */
  syms = slurp_symtabl(abfd, &symcount);

  /* Find the section to use. */
  sect = bfd_get_section_by_name(abfd, SECTION_NAME);
  if (sect == NULL)
    {
      fprintf(stderr, "%s: %s: could not find section `%s'\n",
              optctx.program, symbol_file, SECTION_NAME);
      (void) bfd_close_all_done(abfd);
      return FALSE;
    }

  /* Successfully loaded symbols. */

  file->sect = sect;
  file->abfd = abfd;
  file->num_syms = symcount;
  file->syms = syms;

  return TRUE;
}


static GnuBool
find_nearest_line(unsigned long pc, const char **file, const char **func,
                  int *line)
{
  SymbolFile f;
  PCHashEntry entry;
  unsigned long tpc;

  *file = NULL;
  *func = NULL;
  *line = 0;

  /* Lookup PC from the PC hash. */
  entry = pc_hash_lookup(pc);
  if (entry)
    {
    found:
      *file = entry->filename;
      *func = entry->functionname;
      *line = entry->line;

      return TRUE;
    }

  /* Check symbol files. */
  for (f = symbol_files_head; f; f = f->next)
    {
      if (f->abfd == NULL || f->num_syms == 0)
	/* Not enabled. */
	continue;

      if (pc < f->offset
	  || (f->size && pc >= f->offset + f->size))
        /* Not in this symbol file. */
        continue;

      tpc = pc;
      if (f->sect->vma + f->sect->size < f->offset)
        tpc -= f->offset;

      if (tpc >= f->sect->vma)
        tpc -= f->sect->vma;

      if (tpc >= f->sect->size)
        /* Not in this section. */
        continue;

      if (bfd_find_nearest_line(f->abfd, f->sect, f->syms, tpc,
                                file, func, (unsigned int *) line))
        {
          /* Found a match. */
          entry = pc_hash_add(pc, *file, *func, *line);
          goto found;
        }
    }

  /* Could not find the symbol. */
  return FALSE;
}
#endif /* HAVE_SYMBOL_FILE */


/***************************** Static functions *****************************/

static void
usage(void)
{
  fprintf(stdout,
#if HAVE_SYMBOL_FILE
	  "Usage: %s [OPTION]... PROGRAM [LEAKDUMP]\n"
#else /* not HAVE_SYMBOL_FILE */
	  "Usage: %s [OPTION]... [LEAKDUMP]\n"
#endif /* not HAVE_SYMBOL_FILE */
	  "\
Mandatory arguments to long options are mandatory for short options too.\n\
  -b, --batch                run in batch mode\n\
  -e, --enable-symbol-files  enable additional symbol files automatically\n\
  -f, --fullname             show full source file names in stack trace\n\
  -h, --help                 print this help and exit\n\
  -n, --nx                   do not read `%s' file\n\
  -s, --stdin                read leakdump from stdin, requires -b\n\
  -i, --interactive          run as interactive memory leak check shell\n\
  -o, --output=FILE          save the batch mode output to file FILE.\n\
                             The default is standard output.\n\
  -v, --verbose              tell what the program is doing\n\
  -V, --version              print version number\n\
",
          optctx.program,
          INIT_FILE_NAME);

  fprintf(stdout, "\nReport bugs to mtr@iki.fi.\n");
}


static void
version(void)
{
  printf("%s\n\
Copyright (C) 2005 Markku Rossi.\n\
Stacktrace comes with NO WARRANTY, to the extent permitted by law.\n\
You may redistribute copies of stacktrace under the terms of the GNU\n\
General Public License.  For more information about these matters, see\n\
the files named COPYING.\n",
         version_string);
}


/* The name and line of the current input source. */
const char *input_file = NULL;
int input_line;

/* The name of the current command. */
char *command_name = NULL;

static void
message(char *fmt, ...)
{
  va_list ap;

  if (input_file)
    fprintf(stdout, "%s:%d: ", input_file, input_line);
  else
    fprintf(stdout, "%s: ", optctx.program);

  if (command_name)
    fprintf(stdout, "%s: ", command_name);

  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
}


/**************************** Leak dump parsing *****************************/

static char *prev_line = NULL;
static char *line = NULL;

static int
read_one_line(void)
{
  int ch;
  size_t linelen = 0;

  while ((ch = fgetc(ifp)) != EOF)
    {
      line = gnu_xrealloc(line, linelen + 2);
      line[linelen++] = ch;
      if (ch == '\n')
        break;
      /* As long as there isn't EOF, we still return lines with \n */
    }
  if (linelen == 0)
    return 0;

  /* There is already space for the null-termination. */
  line[linelen] = '\0';

  return 1;
}

static int
is_pc_line(GnuBool *attributes_return)
{
  int s, i;

  /* Check the known signatures. */
  for (s = 0; signatures[s].prefix; s++)
    {
      for (i = 0;
           (signatures[s].prefix[i]
	    && line[i]
	    && signatures[s].prefix[i] == line[i]);
           i++)
        ;
      if (signatures[s].prefix[i] == '\0')
        {
	  /* Signature matched. */
	  if (attributes_return)
	    *attributes_return = signatures[s].attributes;
	  return i;
	}
    }

  /* No match. */
  return 0;
}

static GnuBool
is_stacktrace_end_tag()
{
  if (strncmp(line, "</stacktrace>", 13) == 0)
    return TRUE;

  return FALSE;
}

static int
parse_attrs(char **data, char **name_return, char **value_return)
{
  char *cp = *data;
  char *name = NULL;
  char *value = NULL;

  /* Skip leading whitespace. */
  while (*cp && *cp == ' ')
    cp++;

  if (*cp == '\0')
    return 0;

  /* Read name. */
  name = cp;
  while (*cp && (('a' <= *cp && *cp <= 'z') || *cp == '-'))
    cp++;
  name = gnu_xmemdup(name, cp - name);

  if (*cp != '=')
    goto error;
  cp++;
  if (*cp != '"')
    goto error;
  cp++;

  /* Read value. */

  value = cp;
  while (*cp && *cp != '"')
    cp++;
  if (*cp != '"')
    goto error;

  value = gnu_xmemdup(value, cp - value);

  *name_return = name;
  *value_return = value;
  *data = ++cp;

  return 1;


  /* Error handling. */

 error:
  gnu_xfree(name);
  gnu_xfree(value);

  return 0;
}


static GnuBool
parse_header_line(MemoryLeak leak)
{
  if (prev_line)
    {
      char *cp;
      char *l;

      if (strlen(prev_line) > 12
          && memcmp(prev_line, "<stacktrace>", 12) == 0)
        {
          /* A header line in the new format. */
          l = prev_line + 12;
          cp = strchr(l, ':');
          if (cp == NULL)
            return FALSE;

          /* Found filename. */
          leak->filename = intern(l, cp - l);
          l = cp + 1;

          cp = strchr(l, ':');
          if (cp == NULL)
            return FALSE;

          /* Found line number. */
          leak->line = atoi(l);

          if (sscanf(cp, ": #blocks=%u, bytes=%u",
                     &leak->blocks, &leak->bytes) == 2)
            {
              num_leak_blocks += leak->blocks;
              num_leak_bytes += leak->bytes;
            }
          else
            {
              leak->blocks = 0;
              leak->bytes = 0;
            }
        }
      else if (strlen(prev_line) > 12
               && memcmp(prev_line, "<stacktrace ", 12) == 0)
        {
          char *name;
          char *value;

          /* A header line in the newest format. */
          cp = prev_line + 12;
          while (parse_attrs((char **) &cp, &name, &value))
            {
	      size_t i;

              if (strcmp(name, "blocks") == 0)
                {
                  leak->blocks = atoi(value);
                  num_leak_blocks += leak->blocks;
                }
              else if (strcmp(name, "bytes") == 0)
                {
                  leak->bytes = atoi(value);
                  num_leak_bytes += leak->bytes;
                }
              else if (strcmp(name, "seqnum") == 0)
                {
                  leak->seqnum = atoi(value);
		  leak->has_seqnum = 1;
                }
	      else if (strcmp(name, "data") == 0)
		{
		  leak->data_len = strlen(value) / 2;
		  leak->data = gnu_xmalloc(leak->data_len);

		  for (i = 0; value[i] && value[i + 1]; i += 2)
		    {
		      unsigned char d;

		      d = HEX_TO_INT(value[i]);
		      d <<= 4;
		      d += HEX_TO_INT(value[i + 1]);

		      leak->data[i / 2] = d;
		    }
		}
	      else if (strcmp(name, "file") == 0)
		{
		  for (i = 0; value[i]; i++)
		    if (value[i] == '\\')
		      value[i] = '/';

		  leak->filename = intern(value, strlen(value));
		}
	      else if (strcmp(name, "line") == 0)
		{
		  leak->line = atoi(value);
		}
              else if (strcmp(name, "tag") == 0)
                {
                  leak->tag = intern(value, strlen(value));
                }
              else if (strcmp(name, "type") == 0)
                {
                  leak->type_name = intern(value, strlen(value));

                  if (leak->type_name == intern("handle-open", 0)
                      || leak->type_name == intern("handle-close", 0))
                    leak->type = LEAK_FD;
                }
              if (strcmp(name, "native") == 0)
                {
                  leak->fd = strtoul(value, NULL, 16);
                }
              else if (strcmp(name, "is-open") == 0)
                {
                  if (atoi(value) != 0)
                    leak->fd_is_open = 1;
                  else
                    leak->fd_is_open = 0;
                }
              else if (strcmp(name, "handle-type") == 0)
                {
                  leak->fd_type = intern(value, strlen(value));
                }

              gnu_xfree(name);
              gnu_xfree(value);
            }
        }
      else
        {
          cp = strchr(prev_line, ':');
          if (cp == NULL)
            return FALSE;

          leak->filename = intern(prev_line, cp - prev_line);

          if (sscanf(cp, ":%u: #blocks=%u, bytes=%u",
                     &leak->line, &leak->blocks, &leak->bytes) == 3)
            {
              num_leak_blocks += leak->blocks;
              num_leak_bytes += leak->bytes;
            }
          else
            {
              leak->line = 0;
              leak->blocks = 0;
              leak->bytes = 0;

	      return FALSE;
            }
        }
    }

  return TRUE;
}

static void
update_leak_label(MemoryLeak leak, StackFrame stack_frames,
                  unsigned int num_stack_frames)
{
  unsigned int i;

  for (i = 1; i < num_stack_frames; i++)
    if (stack_frames[i].filename != stack_frames[0].filename
        && !stack_frames[i].leaf)
      break;

  if (i >= num_stack_frames
      || stack_frames[i].filename == NULL)
    i = 0;

  if (stack_frames[i].filename)
    {
      leak->filename = strrchr(stack_frames[i].filename, '/');
      if (leak->filename)
        leak->filename++;
      else
        leak->filename = (char *) stack_frames[i].filename;

      leak->line = stack_frames[i].line;
    }
  else
    {
      leak->filename = "???";
      leak->line = 0;
    }
}

/* Update labels for the leaks which did not have filename in the dump
   file. */
static void
update_leak_labels(void)
{
  MemoryLeak leak;

  for (leak = leaks; leak; leak = leak->next)
    if (leak->dynamic_label)
      {
        if (leak->num_stack_frames)
          {
            update_leak_label(leak, leak->stack_frames,
                              leak->num_stack_frames);
          }
        else if (leak->num_close_stack_frames)
          {
            update_leak_label(leak, leak->close_stack_frames,
                              leak->num_close_stack_frames);
          }
        else
          {
            leak->filename = "???";
            leak->line = 0;
          }
      }
}

/* Update leak info to stack frames. */
static void
update_leak_chain(MemoryLeak leak)
{
  for (; leak; leak = leak->next)
    {
      unsigned int i;

      if (leak->type == LEAK_GROUP)
        {
          update_leak_chain(leak->grouped);
        }
      else
        {
          GnuBool non_leaf_seen = FALSE;

          for (i = 0; i < leak->num_stack_frames; i++)
            {
              StackFrame frame = &leak->stack_frames[i];
              LeafNode leaf;

              frame->leaf = 0;

              if (non_leaf_seen)
                continue;

              /* Autoleaf. */
              if (frame->filename == NULL || frame->line == 0)
                {
                  frame->leaf = 1;
                  continue;
                }

              for (leaf = leaf_nodes_head; leaf; leaf = leaf->next)
                {
                  if (leaf->disabled)
                    continue;

                  if (leaf->filename)
                    {
                      char *cp;

                      if (frame->filename == NULL)
                        continue;

                      /* First try with the suffix. */
                      cp = strrchr(frame->filename, '/');
                      if (cp)
                        {
                          if (gnu_glob_match(leaf->filename, cp + 1)
                              || gnu_glob_match(leaf->filename,
                                                frame->filename))
                            /* Suffix or the full name matched. */
                            break;
                        }
                      else
                        {
                          /* Try only with the full name. */
                          if (gnu_glob_match(leaf->filename, frame->filename))
                            break;
                        }
                    }

                  if (leaf->functionname)
                    {
                      if (frame->functionname != NULL
                          && gnu_glob_match(leaf->functionname,
                                            frame->functionname))
                        /* Function name matched. */
                        break;
                    }
                }

              if (leaf)
                {
                  /* Match. */
                  frame->leaf = 1;
                  leaf->num_matches++;
                }
              else
                {
                  non_leaf_seen = TRUE;
                }
            }
        }
    }
}

/* Select the initial frame for the current leak. */
static void
select_frame(void)
{
  int i;

  assert(current_leak);

  for (i = current_leak->num_stack_frames - 1; i >= 0; i--)
    if (current_leak->stack_frames[i].leaf)
      break;

  if (i < current_leak->num_stack_frames - 1)
    i++;
  if (i < 0)
    i = 0;

  current_frame = i;
}

static void
rescan_symbols(void)
{
#if HAVE_SYMBOL_FILE
  MemoryLeak leak;
  unsigned int i;

  /* Clear PC hash. */
  pc_hash_clear();

  /* Scan leaks. */
  for (leak = leaks; leak; leak = leak->next)
    for (i = 0; i < leak->num_stack_frames; i++)
      {
        StackFrame f = &leak->stack_frames[i];
        const char *file;
        const char *func;
        int line;

        if (find_nearest_line(f->pc, &file, &func, &line))
          {
            f->filename = file;
            f->functionname = func;
            f->line = line;
          }
      }
#endif /* HAVE_SYMBOL_FILE */
}

static void
add_leak(MemoryLeak leak)
{
  /* Update statistics. */
  num_leak_frames += leak->num_stack_frames * leak->blocks;

  /* Let's have dynamic labels on all leaks. */
  leak->dynamic_label = 1;

  /* Read one leak. */
  if (leaks_tail)
    {
      leaks_tail->next = leak;
      leak->prev = leaks_tail;
    }
  else
    {
      leaks = leak;
    }
  leaks_tail = leak;
  num_leaks++;
}

static void
read_stacktrace(StackFrame *framep, unsigned int *nump,
                int i, GnuBool attributes)
{
  int j;
  char *cp;
  char *name;
  char *value;
  StackFrame frame;

  do
    {
      /* We managed to parse a new stackframe. */

      *framep = gnu_xrealloc(*framep, (*nump + 1) * sizeof(StackFrameStruct));
      frame = &(*framep)[(*nump)++];
      memset(frame, 0, sizeof(*frame));

      if (attributes)
        {
          /* The new attribute <pc> format. */
          cp = line + i;
          while (parse_attrs(&cp, &name, &value))
            {
              if (strcmp(name, "file") == 0)
                {
                  /* Canonize path separators. */
                  for (j = 0; value[j]; j++)
                    if (value[j] == '\\')
                      value[j] = '/';

                  frame->filename = intern(value, strlen(value));
                }
              else if (strcmp(name, "line") == 0)
                {
                  frame->line = atoi(value);
                }
              else if (strcmp(name, "function") == 0)
                {
                  frame->functionname = intern(value, strlen(value));
                }
              else if (strcmp(name, "pc") == 0)
                {
                  frame->pc = strtoul(value, NULL, 0);
                }

              gnu_free(name);
              gnu_free(value);
            }
        }
      else
        {
          /* The traditional CDATA format. */
          frame->pc = strtoul(line + i, NULL, 16);
        }

#if HAVE_SYMBOL_FILE
      if (frame->functionname == NULL)
        (void) find_nearest_line(frame->pc,
                                 &frame->filename,
                                 &frame->functionname,
                                 &frame->line);
#endif /* HAVE_SYMBOL_FILE */

      /* Print this frame. */
      if (batch)
        {
          const char *cp = NULL;

          if (frame->filename)
            {
              if (fullname)
                {
                  cp = frame->filename;
                }
              else
                {
                  cp = strrchr(frame->filename, '/');
                  if (cp)
                    cp++;
                  else
                    cp = frame->filename;
                }
            }

          fputs("  ", ofp);
          if (cp)
            fprintf(ofp, "%s:%d: ", cp, frame->line);
          fprintf(ofp, "%s()\n",
                  frame->functionname ? frame->functionname : "???");
        }

      /* Read more. */
      if (!read_one_line())
        break;

      i = is_pc_line(NULL);
      if (i == 0)
        {
          if (batch)
            {
              fputs(line, ofp);
              putc('\n', ofp);
            }
          break;
        }
    }
  while (1);
}

static void
read_dump_file(void)
{
  int num_symbol_files = 0;

  while (read_one_line())
    {
      int i;
      GnuBool attributes;
      char *cp;
      char *name;
      char *value;
      MemoryLeak leak;
      StackFrame frame;

      /* Check additional symbol files. */
      if (strlen(line) > 13
	  && memcmp(line, "<symbol-file ", 13) == 0)
	{
	  char *offset = NULL;
	  char *size = NULL;
	  char *file = NULL;

	  /* A symbol file specification found. */

	  cp = line + 13;
	  while (parse_attrs(&cp, &name, &value))
	    {
	      if (strcmp(name, "offset") == 0)
		offset = value;
	      else if (strcmp(name, "size") == 0)
		size = value;
	      else if (strcmp(name, "file") == 0)
		file = value;
	      else
		{
		  /* Ignore unknown tags. */
		  gnu_free(name);
		  gnu_free(value);
		}
	    }
	  if (file && offset && size)
	    {
#if HAVE_SYMBOL_FILE
	      if (!add_symbol_file(file,
				   strtoul(offset, NULL, 16),
				   strtoul(size, NULL, 16)))
		continue;

	      if (enable_symbol_files
		  && !enable_symbol_file(file))
		continue;

	      rescan_symbols();
	      num_symbol_files++;
#endif /* HAVE_SYMBOL_FILE */
	    }

	  gnu_free(file);
	  gnu_free(size);
	  gnu_free(offset);

	  continue;
	}

      /* Rescan symbols if any additional symbol files were enabled. */
      if (num_symbol_files)
	{
	  rescan_symbols();
	  num_symbol_files = 0;
	}

      i = is_pc_line(&attributes);
      if (i)
        {
          MemoryLeak leak;

          /* Found a match. */
          leak = gnu_xcalloc(1, sizeof(*leak));

          if (!parse_header_line(leak))
	    {
	      gnu_free(leak);
	      goto next_line;
	    }

          read_stacktrace(&leak->stack_frames, &leak->num_stack_frames,
                          i, attributes);

	  /* Add leak to our list of memory leaks. */
	  add_leak(leak);
        }
      else if (is_stacktrace_end_tag())
	{
	  /* Found an end tag. */
	  leak = gnu_xcalloc(1, sizeof(*leak));

	  if (!parse_header_line(leak))
	    {
	      /* The previous line was not a header line.  Ignore this
		 tag. */
	      gnu_free(leak);
	      goto next_line;
	    }

	  /* End-tag preceded by a header line.  This is a leak
	     without stacktrace.  Let's generate one pseudo frame from
	     the header information. */

	  frame = gnu_xcalloc(1, sizeof(*frame));
	  leak->stack_frames = frame;
	  leak->num_stack_frames = 1;

	  frame->filename = leak->filename;
	  frame->line = leak->line;

	  /* Function name is not available. */
	  frame->functionname = "???";

	  /* Add leak to our list of memory leaks. */
	  add_leak(leak);
	}
      else
        {
          /* The signature did not match. */
          if (batch)
            fputs(line, ofp);
        }

    next_line:

      gnu_xfree(prev_line);
      prev_line = line;
      line = NULL;
    }
  gnu_xfree(line);

  /* Update dynamic leak labels. */
  update_leak_labels();

  /* Autoleaf frames. */
  update_leak_chain(leaks);

  global_leak_info();

  if (0)
    {
      MemoryLeak leak;

      for (leak = leaks; leak; leak = leak->next)
        {
          unsigned int i;

          printf("%s:%u: %u blocks, %u bytes\n",
                 leak->filename, leak->line,
                 leak->blocks, leak->bytes);

          for (i = 0; i < leak->num_stack_frames; i++)
            printf("  %s:%d: %s\n",
                   leak->stack_frames[i].filename,
                   leak->stack_frames[i].line,
                   leak->stack_frames[i].functionname);
        }
    }

  current_leak = leaks;

  if (current_leak)
    select_frame();
}


/******************* Interactive memory leak check shell ********************/

#define CMD(name, synopsis, help)                       \
static char *cmd_ ## name ## _synopsis = synopsis;      \
static char *cmd_ ## name ## _help = help;              \
                                                        \
static int                                              \
cmd_ ## name(int argc, char *argv[])

#define CMDD(name,  min, max, location) \
  #name, NULL, min, max, cmd_ ## name,  \
  & cmd_ ## name ## _synopsis,          \
  & cmd_ ## name ## _help,              \
  location

#define CMDDD(cname, name, min, max, location)  \
  cname, NULL, min, max, cmd_ ## name,          \
  & cmd_ ## name ## _synopsis,                  \
  & cmd_ ## name ## _help,                      \
  location

#define CMD_ALIAS(name, alias_of)       \
  #name, #alias_of, 0, 0, NULL, NULL, NULL, 0

#define NEED_LEAKS()                            \
do                                              \
  {                                             \
    if (!leaks)                                 \
      {                                         \
        message("No leak dump loaded.\n");      \
        return 0;                               \
      }                                         \
  }                                             \
while (0)

CMD(long,
    "Output information used by emacs-stacktrace interface.",
    "\
If the emacs-stacktrace interface is enabled, the stacktrace program\n\
generates special output so that the Emacs's can locate source files.\n\
The interface works by generating special output tokens which are recognized\n\
by Emacs.  See the `stacktrace.el' for the details.")
{
  fullname = 1;
  return 0;
}


CMD(short, "Disable emacs-stacktrace interface.", NULL)
{
  fullname = 0;
  return 0;
}

CMD(echo, "Print argument strings to standard output.", NULL)
{
  int i;

  for (i = 1; i < argc; i++)
    {
      if (i > 1)
	printf(" ");
      printf("%s", argv[i]);
    }

  printf("\n");

  return 0;
}

CMD(add_symbol_file, "Load the symbols from FILE.",
    "\
The ADDR is the starting address of the file's text segment.")
{
#if HAVE_SYMBOL_FILE
  if (add_symbol_file(argv[1], strtoul(argv[2], NULL, 0), 0)
      && enable_symbol_file(argv[1]))
    {
      /* Symbol file loaded.  Now rescan leaks. */
      rescan_symbols();

      /* And update dynamic leak labels. */
      update_leak_labels();
    }
  else
    {
      fprintf(stderr, "%s: Could not add symbol file `%s'\n",
              optctx.program, argv[1]);
    }
#else /* not HAVE_SYMBOL_FILE */
  printf("No symbol file support.\n");
#endif /* not HAVE_SYMBOL_FILE */

  return 0;
}

static void
print_location(void)
{
  StackFrame frame;

  if (!fullname)
    return;

  if (!current_leak || !current_leak->stack_frames)
    return;

  frame = &current_leak->stack_frames[current_frame];
  if (!frame->filename || frame->line == 0)
    return;

  printf("\032\032%s%s%s:%u:%lu\n",
         root_dir ? root_dir : "",
         root_dir ? "/" : "",
         frame->filename,
         frame->line,
         frame->pc);
}


static void
global_leak_info(void)
{
  printf("%s: %u memory leaks, %lu blocks, %lu bytes",
         exe, num_leaks, num_leak_blocks, num_leak_bytes);
  if (num_leak_blocks)
    printf(", avg stack depth %.2f",
           (double) num_leak_frames / num_leak_blocks);

  printf("\n");
}


static void
leak_info(void)
{
  char *unit;
  unsigned int bytes;
  char *stacktrace_type;

  if (!current_leak)
    return;

  if (current_leak->bytes > 1024 * 1024)
    {
      unit = "kB";
      bytes = current_leak->bytes / 1024;
    }
  else if (current_leak->bytes > 1024 * 1024 * 1024)
    {
      unit = "MB";
      bytes = current_leak->bytes / 1024 / 1024;
    }
  else
    {
      unit = "bytes";
      bytes = current_leak->bytes;
    }

  switch (current_leak->type)
    {
    case LEAK_MEM:
    case LEAK_GROUP:
      printf("%s  %u/%u at %s%s%u%s %u block%s, %u %s (%.2f%%)",
             current_leak->type == LEAK_GROUP ? "Group" : "Leak ",

             current_leak_index + 1, num_leaks,
             current_leak->filename,

             current_leak->type == LEAK_GROUP ? "[" : ":",
             current_leak->line,
             current_leak->type == LEAK_GROUP ? "]" : ":",

             current_leak->blocks,
             current_leak->blocks == 1 ? "" : "s",
             bytes, unit,
             current_leak->bytes / (double) num_leak_bytes * 100);

      if (current_leak->has_seqnum)
        printf(", #%u", current_leak->seqnum);

      printf("\n");
      break;

    case LEAK_FD:
      if (current_leak->type_name == intern("handle-open", 0))
        stacktrace_type = "open, ";
      else
        stacktrace_type = "close,";

      printf("FD-%-3lu %u/%u at %s:%u: %s fd=%s(%s)\n",
             current_leak->fd,
             current_leak_index + 1, num_leaks,
             current_leak->filename, current_leak->line,
             stacktrace_type,

             current_leak->fd_type,
             current_leak->fd_is_open ? "open" : "closed");
      break;
    }
}


static void
frame_info_only(unsigned int frame)
{
  StackFrame f;

  if (current_leak->type == LEAK_GROUP)
    /* No frames in groups. */
    return;

  printf("#%-2u ", frame);

  f = &current_leak->stack_frames[frame];

  if (f->filename && f->line)
    {
      const char *cp;

      cp = strrchr(f->filename, '/');
      if (cp)
        cp++;
      else
        cp = f->filename;

      printf("%s() at %s:%d%s\n", f->functionname, cp, f->line,
             f->leaf ? " (leaf)" : "");
    }
  else
    {
      printf("0x%08lx in %s()%s\n", f->pc,
             f->functionname ? f->functionname : "???",
             f->leaf ? " (leaf)" : "");
    }
}


static void
frame_info(void)
{
  frame_info_only(current_frame);
}


CMD(frame, "Print information about current stack frame.",
    "\
If the argument NTH is given, select the NTH frame and print information\n\
about it.")
{
  NEED_LEAKS();

  if (current_leak->type == LEAK_GROUP)
    {
      printf("%s: no frames in groups\n", argv[0]);
      leak_info();
    }
  else
    {
      if (argc == 2)
        {
          int new_frame = atoi(argv[1]);

          if (new_frame < 0 || new_frame >= current_leak->num_stack_frames)
            printf("%s: frame index out of range [0...%d]\n",
                   argv[0], current_leak->num_stack_frames);
          else
            current_frame = new_frame;
        }
      frame_info();
    }

  return 0;
}


CMD(next, "Move to the next memory leak.", NULL)
{
  NEED_LEAKS();

  if (current_leak->next)
    {
      current_leak = current_leak->next;
      current_leak_index++;
      select_frame();
      leak_info();
    }
  else
    {
      printf("Last leak selected; you cannot go forward.\n");
    }

  return 0;
}


CMD(previous, "Move to the previous memory leak.", NULL)
{
  NEED_LEAKS();

  if (current_leak->prev)
    {
      current_leak = current_leak->prev;
      current_leak_index--;
      select_frame();
      leak_info();
    }
  else
    {
      printf("First leak selected; you cannot go backward.\n");
    }

  return 0;
}

CMD(fd, "Select leak with the specified file descriptor value.", NULL)
{
  unsigned long fd;
  MemoryLeak leak;
  unsigned int index;

  NEED_LEAKS();

  fd = strtoul(argv[1], NULL, 0);

  for (index = 0, leak = leaks;
       leak && leak->fd != fd;
       index++, leak = leak->next)
    ;

  if (leak == NULL)
    {
      printf("No leak with FD %lu\n", fd);
      return 0;
    }

  current_leak = leak;
  current_leak_index = index;

  leak_info();

  return 0;
}


CMD(leak, "Print information about current memory leak.",
    "\
If the argument NTH is given, select the NTH memory leak and print\n\
information about it.")
{
  int leak;

  NEED_LEAKS();

  if (argc > 1)
    {
      /* Select a leak. */
      leak = atoi(argv[1]);

      if (leak < 1 || leak > num_leaks)
        {
          printf("%s: leak index out of range [1...%d]\n",
                 argv[0], num_leaks);
          return 0;
        }

      current_leak_index = 0;
      select_frame();

      for (current_leak = leaks;
           current_leak && current_leak_index < leak - 1;
           current_leak = current_leak->next, current_leak_index++)
        ;

      if (current_leak == NULL)
        {
          current_leak = leaks;
          current_leak_index = 0;
        }
    }

  leak_info();

  return 0;
}

static void
update_leaf_nodes(void)
{
  LeafNode leaf;

  /* Reset leaf match counts. */
  for (leaf = leaf_nodes_head; leaf; leaf = leaf->next)
    leaf->num_matches = 0;

  /* Update leaks. */
  update_leak_chain(leaks);
}

CMD(leaf, "Mark leaks as leafs of stacktraces.",
    "\
The leaf leaks can be specify by function name, by file name, or by both:\n\
  FILE.*                file name ending with suffix\n\
  FILE:FUNCTION         file name and function name\n\
  FUNCTION()            an explicit function name\n\
  FUNCTION              an implicit function name without parenthesis\n\
The file and function names can contain normal glob patterns.  When\n\
viewing stacktraces, the program starts showing the stacktrace from\n\
a leaf leak or from the botton of the stacktrace.")
{
  int i;

  NEED_LEAKS();

  /* Process arguments. */
  for (i = 1; i < argc; i++)
    {
      LeafNode leaf = gnu_xcalloc(1, sizeof(*leaf));

      if (gnu_glob_match("*.*", argv[i]))
        {
          /* File name. */
          leaf->filename = gnu_xstrdup(argv[i]);
        }
      else if (gnu_glob_match("*()", argv[i]))
        {
          /* Function name. */
          leaf->functionname = gnu_xmemdup(argv[i], strlen(argv[i]) - 2);
        }
      else if (gnu_glob_match("*:*", argv[i]))
        {
          char *cp;

          /* File and function name. */
          cp = strchr(argv[i], ':');
          assert(cp != NULL);

          leaf->filename = gnu_xmemdup(argv[i], cp - argv[i]);
          leaf->functionname = gnu_xstrdup(cp + 1);
        }
      else
        {
          /* An implicit function name. */
          leaf->functionname = gnu_xstrdup(argv[i]);
        }

      /* Add it to our list of leaf nodes. */
      if (leaf_nodes_tail)
        leaf_nodes_tail->next = leaf;
      else
        leaf_nodes_head = leaf;

      leaf_nodes_tail = leaf;

      leaf->index = next_leaf_index++;
    }

  update_leaf_nodes();
  update_leak_labels();
  select_frame();

  /* All done. */
  return 0;
}

CMD(up, "Select and print stack frame that called this one.", NULL)
{
  NEED_LEAKS();

  if (current_frame + 1 >= current_leak->num_stack_frames)
    {
      printf("Initial frame selected; you cannot go up.\n");
      return 0;
    }
  current_frame++;

  frame_info();

  return 0;
}


CMD(down, "Select and print stack frame called by this one.", NULL)
{
  NEED_LEAKS();

  if (current_frame == 0)
    {
      printf("Bottom (i.e., innermost) frame selected; you cannot go down.\n");
      return 0;
    }
  current_frame--;

  frame_info();

  return 0;
}


CMD(backtrace, "Print backtrace of all stack frames.", NULL)
{
  unsigned int i;

  NEED_LEAKS();

  for (i = 0; i < current_leak->num_stack_frames; i++)
    frame_info_only(i);

  return 0;
}

static void
list_file(const char *name, unsigned int linenum)
{
  unsigned int l;

  ifp = fopen(name, "rb");
  if (ifp == NULL)
    {
      fprintf(stderr, "Could not open file `%s': %s\n",
              name, strerror(errno));
      return;
    }

  /* Skip until the start line is reached. */
  for (l = 1; l < linenum && read_one_line(); l++)
    ;

  if (l < linenum)
    {
      const char *cp;

      cp = strrchr(name, '/');
      if (cp)
        cp++;
      else
        cp = name;

      fprintf(stderr, "Line number %u out of range; %s has %u lines.\n",
              linenum, cp, l - 1);
      goto out;
    }

  /* Print ten lines. */
  for (l = 0; l < 10 && read_one_line(); l++)
    fprintf(stdout, "%-8u%s", linenum + l, line);

 out:
  fclose(ifp);
}

CMD(list, "List current line.", NULL)
{
  static const char *filename = NULL;
  static unsigned int linenum;
  int linenum_arg = 0;

  NEED_LEAKS();

  if (argc == 2)
    {
      if (strcmp(argv[1], "-") == 0)
        linenum_arg = -10;
      else
        linenum_arg = atoi(argv[1]);
    }

  if (last_command == cmd_list)
    {
      if (filename)
        {
          if (linenum_arg > 0)
            linenum = linenum_arg;
          else if (linenum_arg < 0)
            linenum -= -linenum_arg * 2;

          list_file(filename, linenum);
          linenum += 10;
        }
      else
        {
          fprintf(stderr, "%s: No file name\n", optctx.program);
        }
    }
  else
    {
      if (current_leak->stack_frames
          && current_leak->stack_frames[current_frame].filename)
        {
          filename = current_leak->stack_frames[current_frame].filename;
          linenum = current_leak->stack_frames[current_frame].line;

          if (linenum_arg > 0)
            linenum = linenum_arg;
          else if (linenum_arg < 0)
            linenum -= -linenum_arg;

          if (linenum > 5)
            linenum -= 5;

          list_file(filename, linenum);
          linenum += 10;
        }
      else
        {
          fprintf(stderr, "%s: No file name\n", optctx.program);
          filename = NULL;
        }
    }

  return 0;
}


CMD(pc, "Locate single program counter value.", NULL)
{
#if HAVE_SYMBOL_FILE
  unsigned long pc;
  const char *filename;
  const char *functionname;
  int line;

  /* Locate single PC value. */
  pc = strtoul(argv[1], NULL, 0);

  if (find_nearest_line(pc, &filename, &functionname, &line))
    {
      if (filename && line)
        {
          const char *cp;

          cp = strrchr(filename, '/');
          if (cp)
            cp++;
          else
            cp = filename;

          printf("%s:%d: %s()\n", cp, line, functionname);
        }
      else
        printf("%s()\n", functionname);
    }
#else /* not HAVE_SYMBOL_FILE */
  printf("No symbol file support.\n");
#endif /* not HAVE_SYMBOL_FILE */

  return 0;
}

CMD(scan, "Scan symbol files for program counter value.", NULL)
{
#if HAVE_SYMBOL_FILE
  unsigned long pc, tpc;
  const char *filename;
  const char *functionname;
  unsigned int line;
  SymbolFile f;

  /* Scan symbol files for PC value. */
  pc = strtoul(argv[1], NULL, 0);

  for (f = symbol_files_head; f; f = f->next)
    {
      if (f->abfd == NULL)
        /* Not enabled. */
        continue;

      printf("%-35.35s:\t", f->symbol_file);

      if (pc < f->offset
	  || (f->size && pc >= f->offset + f->size))
        {
          /* Not in this symbol file. */
          printf("not in range [%p-%p]\n",
                 (void *) f->offset,
                 (void *) f->offset + f->size);
          continue;
        }

      tpc = pc;
      if (f->sect->vma + f->sect->size < f->offset)
        tpc -= f->offset;

      if (tpc >= f->sect->vma)
        tpc -= f->sect->vma;

      if (tpc >= f->sect->size)
        {
          printf("not in range [%p-%p]\n",
                 (void *) (long) (f->sect->vma),
                 (void *) (long) (f->sect->vma + f->sect->size));
          continue;
        }

      if (bfd_find_nearest_line(f->abfd, f->sect, f->syms, tpc,
                                &filename, &functionname, &line))
        {
          /* Found a match. */
          printf("%s:%d: %s()\n", filename, line, functionname);
        }
      else
        {
          printf("not found\n");
        }
    }

#else /* not HAVE_SYMBOL_FILE */
  printf("No symbol file support.\n");
#endif /* not HAVE_SYMBOL_FILE */

  return 0;
}


CMD(quit, "Exit stacktrace.", NULL)
{
  return 1;
}


/******************************* Info command *******************************/

static void
info_global(void)
{
  global_leak_info();
  leak_info();
}

static void
info_leaf(void)
{
  LeafNode leaf;

  if (leaf_nodes_head == NULL)
    {
      printf("No leaf node selectors.\n");
      return;
    }

  printf("Num Enb Matches What\n");
  /*      1   y   7       foo.c:xmalloc_i */
  for (leaf = leaf_nodes_head; leaf; leaf = leaf->next)
    {
      printf("%-3d %s   %-7d %s%s%s%s\n",
             leaf->index,
             leaf->disabled ? "n" : "y",
             leaf->num_matches,
             leaf->filename ? leaf->filename : "",
             leaf->filename && leaf->functionname ? ":" : "",
             leaf->functionname ? leaf->functionname : "",
             leaf->functionname ? "()" : "");
    }
}

static void
info_groups(void)
{
  MemoryLeak leak;
  int matches = 0;

  for (leak = leaks; leak; leak = leak->next)
    if (leak->type == LEAK_GROUP)
      {
        char *how;

        matches++;

        switch (leak->group_type)
          {
          case GROUP_BY_FILE:
            how = "file";
            break;

          case GROUP_BY_FUNCTION:
            how = "function";
            break;

          case GROUP_BY_LEAK:
            how = "leak";
            break;
          }
        printf("group %s %s\n", how, leak->filename);
      }

  if (matches == 0)
    printf("No leak groups defined\n");
}

static void
info_symbol_files(void)
{
#if HAVE_SYMBOL_FILE
  SymbolFile f;
  int i = 1;

  printf("#   E  Syms Range             VMA      Path\n"
         "\
---------------------------------------------------------------------------\n");
  for (f = symbol_files_head; f; f = f->next)
    {
      if (f->num_syms == 0)
        continue;

      printf("%-3d %s %5lu %08x-%08x %08x %s\n",
             i++, f->abfd ? "y" : "n", f->num_syms,
             (unsigned int) (f ? f->offset : 0),
             (unsigned int) (f ? f->offset + f->size - 1 : 0),
             (unsigned int) (f && f->sect ? f->sect->vma : 0),
             f->symbol_file);
    }
#else /* not HAVE_SYMBOL_FILE */
  printf("No symbol file support.\n");
#endif /* not HAVE_SYMBOL_FILE */
}

static void
info_root(void)
{
  if (root_dir)
    printf("%s\n", root_dir);
  else
    printf("No root directory specified\n");
}


static struct
{
  char *name;
  void (*command)(void);
  char *description;
} info_commands[] =
{
  {"global",		info_global, "Print information about current state"},
  {"leaf",		info_leaf,   "Describe leaf frame selectors"},
  {"groups",		info_groups, "Describe leak groups"},
  {"symbol-files",	info_symbol_files, "Describe symbol files"},
  {"root",		info_root,   "Print current root directory"},
  {NULL, NULL, NULL},
};

CMD(info,
    "Print infomation about current state.",
    "\
Possible subcommands are:\n\
  - global        print global information.  This is the default action if\n\
                  subcommand was specified.\n\
  - leaf          describe leaf frame selectors\n\
  - groups        describe leak groups\n\
  - symbol-files  print symbol files\n\
  - root	  print current root directory\n")
{
  if (argc == 1)
    {
      info_global();
      print_location();
    }
  else
    {
      int i;

      /* XXX Need an utility function to select prefixes from an
         array. */
      for (i = 0; info_commands[i].name; i++)
        if (strcmp(argv[1], info_commands[i].name) == 0)
          {
            (*info_commands[i].command)();
            break;
          }

      if (info_commands[i].name == NULL)
        {
          printf("Undefined info command: \"%s\".  Try \"help info\".\n",
                 argv[1]);
        }
    }

  return 0;
}

static int
sort_by_bytes(const void *a, const void *b)
{
  const MemoryLeak *la = a;
  const MemoryLeak *lb = b;

  if ((*la)->bytes > (*lb)->bytes)
    return -1;

  if ((*la)->bytes < (*lb)->bytes)
    return 1;

  return 0;
}

static int
sort_by_blocks(const void *a, const void *b)
{
  const MemoryLeak *la = a;
  const MemoryLeak *lb = b;

  if ((*la)->blocks > (*lb)->blocks)
    return -1;

  if ((*la)->blocks < (*lb)->blocks)
    return 1;

  return 0;
}

static int
sort_by_frames(const void *a, const void *b)
{
  const MemoryLeak *la = a;
  const MemoryLeak *lb = b;

  if ((*la)->num_stack_frames > (*lb)->num_stack_frames)
    return -1;

  if ((*la)->num_stack_frames < (*lb)->num_stack_frames)
    return 1;

  return 0;
}

static int
sort_by_seqnum(const void *a, const void *b)
{
  const MemoryLeak *la = a;
  const MemoryLeak *lb = b;

  if ((*la)->seqnum < (*lb)->seqnum)
    return -1;

  if ((*la)->seqnum > (*lb)->seqnum)
    return 1;

  return 0;
}

static int
sort_by_tag(const void *a, const void *b)
{
  const MemoryLeak *la = a;
  const MemoryLeak *lb = b;

  return strcmp((*la)->tag, (*lb)->tag);
}

CMD(sort,
    "Sort memory leaks.",
    "\
If the argument CRITERIA is given, sort by that CRITERIA.  Possible values\n\
are:\n\
  - bytes       sort by leaked bytes (default)\n\
  - blocks      sort by number of leaked blocks\n\
  - frames      sort by stack trace depth\n\
  - seqnum      sort by allocation sequence number\n\
  - tag         sort by user-specified tag")
{
  MemoryLeak *buffer, leak;
  int i;
  int (*compare)(const void *, const void *) = sort_by_bytes;

  NEED_LEAKS();

  if (argc == 2)
    {
      if (strcmp(argv[1], "bytes") == 0)
        compare = sort_by_bytes;
      else if (strcmp(argv[1], "blocks") == 0)
        compare = sort_by_blocks;
      else if (strcmp(argv[1], "frames") == 0)
        compare = sort_by_frames;
      else if (strcmp(argv[1], "seqnum") == 0)
        compare = sort_by_seqnum;
      else if (strcmp(argv[1], "tag") == 0)
        compare = sort_by_tag;
      else
        {
          printf("Unknown sorting criteria `%s'.\n", argv[1]);
          return 0;
        }
    }

  buffer = gnu_xcalloc(num_leaks, sizeof(*buffer));

  for (i = 0, leak = leaks; leak; leak = leak->next)
    buffer[i++] = leak;

  assert(i == num_leaks);

  qsort(buffer, num_leaks, sizeof(*buffer), compare);

  leaks = leaks_tail = buffer[0];
  leaks->next = leaks->prev = NULL;

  for (i = 1; i < num_leaks; i++)
    {
      leaks_tail->next = buffer[i];
      leaks_tail->next->prev = leaks_tail;

      leaks_tail = buffer[i];
      leaks_tail->next = NULL;
    }

  current_leak = leaks;
  current_leak_index = 0;

  return 0;
}


CMD(dump,
    "Dump memory leaks.",
    "\
If the argument COUNT is given, dump at maximum that many leaks.\n")
{
  unsigned int count = (unsigned int) -1;
  unsigned int current_index;
  unsigned int i;

  NEED_LEAKS();

  if (argc == 2)
    count = atoi(argv[1]);

  current_index = current_leak_index;

  for (current_leak = leaks, i = 0, current_leak_index = 0;
       current_leak && i < count;
       current_leak = current_leak->next, i++, current_leak_index++)
    leak_info();

  for (current_leak = leaks, i = 0;
       i < current_index;
       current_leak = current_leak->next, i++)
    ;

  current_leak_index = current_index;

  return 0;
}


CMD(group,
    "Group memory leaks.",
    "\
The argument TYPE specifies how grouping is done.  Possible values\n\
are `file', `function', and `leak' to group by file name, function name,\n\
and leak number respectively.  The argument PATTERN gives a glob-like\n\
grouping pattern.\n\
\n\
For the `file' grouping method the pattern can be given as PATTERN:LINE\n\
where PATTERN is glob-like pattern and LINE is line number.\n")
{
  LeakGroupType how;
  MemoryLeak leak;
  MemoryLeak group;
  int index;

  NEED_LEAKS();

  if (strcmp(argv[1], "file") == 0)
    how = GROUP_BY_FILE;
  else if (strcmp(argv[1], "function") == 0)
    how = GROUP_BY_FUNCTION;
  else if (strcmp(argv[1], "leak") == 0)
    how = GROUP_BY_LEAK;
  else
    {
      printf("Unknown grouping type `%s'.\n", argv[1]);
      return 0;
    }

  group = gnu_xcalloc(1, sizeof(*group));
  group->type = LEAK_GROUP;
  group->group_type = how;
  group->filename = gnu_xstrdup(argv[2]);

  for (index = 1, leak = leaks; leak; index++, leak = leak->next)
    {
      int i, j;

      for (i = 2; i < argc; i++)
        switch (how)
          {
          case GROUP_BY_FILE:
            {
              char *pattern;
              int line;
              char *cp;

              /* As a default, no line pattern. */
              pattern = gnu_xstrdup(argv[i]);
              line = 0;

              /* Check for the line number part. */
              cp = strrchr(argv[i], ':');
              if (cp)
                {
                  char *end;

                  line = strtoul(cp + 1, &end, 10);
                  if (*end == '\0')
                    {
                      /* We have a line number pattern. */
                      gnu_xfree(pattern);
                      pattern = gnu_xmemdup(argv[i], cp - argv[i]);
                    }
                }

              /* Do the matching. */
              for (j = 0; j < leak->num_stack_frames; j++)
                if (leak->stack_frames[j].filename)
                  {
                    cp = strrchr(leak->stack_frames[j].filename, '/');
                    if (cp)
                      cp++;
                    else
                      cp = (char *) leak->stack_frames[j].filename;

                    if (gnu_glob_match(pattern, cp)
                        && (line == 0 || line == leak->stack_frames[j].line))
                      {
                        gnu_free(pattern);
                        goto mark;
                      }
                  }

              gnu_free(pattern);
            }
            break;

          case GROUP_BY_FUNCTION:
            for (j = 0; j < leak->num_stack_frames; j++)
              if (gnu_glob_match(argv[i], leak->stack_frames[j].functionname))
                goto mark;
            break;

          case GROUP_BY_LEAK:
            if (atoi(argv[i]) == index)
              goto mark;
            break;
          }

      continue;

    mark:
      leak->marked = 1;
    }

  for (leak = leaks; leak; )
    if (leak->marked)
      {
        MemoryLeak l;

        leak->marked = 0;

        group->blocks += leak->blocks;
        group->bytes += leak->bytes;
        group->line++;

        l = leak;
        leak = leak->next;

        if (l->next)
          l->next->prev = l->prev;

        if (l->prev)
          l->prev->next = l->next;
        else
          leaks = l->next;

        l->next = group->grouped;
        if (l->next)
          l->next->prev = l;

        l->prev = NULL;

        group->grouped = l;
      }
    else
      {
        leak = leak->next;
      }


  group->next = leaks;
  if (group->next)
    group->next->prev = group;

  leaks = group;

  for (num_leaks = 0, leak = leaks; leak; leak = leak->next)
    num_leaks++;

  current_leak = leaks;
  current_leak_index = 0;
  current_frame = 0;

  return 0;
}

CMD(ungroup,
    "Ungroup memory leak groups.",
    "\
The arguments specify which groups are ungrouped.  A numeric argument\n\
specifies the groups index in the current leak listing.  The keyword `all'\n\
ungroups all groups.\n")
{
  MemoryLeak leak;
  enum { ALL, INDEX } how;
  int index;

  NEED_LEAKS();

  if (strcmp(argv[1], "all") == 0)
    how = ALL;
  else
    how = INDEX;

  for (index = 1, leak = leaks; leak; index++, leak = leak->next)
    {
      if (leak->type != LEAK_GROUP)
        continue;

      if (how == ALL)
        {
          leak->marked = 1;
        }
      else
        {
          int i;

          for (i = 1; i < argc; i++)
            if (atoi(argv[i]) == index)
              leak->marked = 1;
        }
    }

  for (leak = leaks; leak; )
    {
      MemoryLeak l;

      if (!leak->marked)
        {
          leak = leak->next;
          continue;
        }

      l = leak;
      leak = leak->next;

      if (l->next)
        l->next->prev = l->prev;

      if (l->prev)
        l->prev->next = l->next;
      else
        leaks = l->next;

      /* Ungroup this group. */
      while (l->grouped)
        {
          MemoryLeak t = l->grouped;

          l->grouped = l->grouped->next;

          t->next = leaks;
          if (t->next)
            t->next->prev = t;

          t->prev = NULL;
          leaks = t;
        }

      gnu_xfree(l);
    }

  for (num_leaks = 0, leak = leaks; leak; leak = leak->next)
    num_leaks++;

  current_leak = leaks;
  current_leak_index = 0;

  return 0;
}

CMD(enable,
    "Enable objects.",
    "\
The argument TYPE specifies what object is enabled.  Possible objects are:\n\
\n\
  leaf		Enable leaf frames\n\
  symbol-files  Enable symbol-files\n\
\n\
Give object numbers (separated by spaces) as arguments.\n")
{
  if (strcmp(argv[1], "symbol-file") == 0)
    {
#if HAVE_SYMBOL_FILE
      SymbolFile f;
      GnuBool enabled = FALSE;
      int i;

      /* Enable symbol files. */
      for (i = 2; i < argc; i++)
	{
	  int num = atoi(argv[i]);
	  int count;

	  for (count = 1, f = symbol_files_head;
	       f && count < num;
	       count++, f = f->next)
	    ;
	  if (f == NULL)
	    {
	      printf("Invalid symbol file index %s.\n", argv[i]);
	    }
	  else
	    {
	      if (enable_symbol_file(f->symbol_file))
		enabled = TRUE;
	    }
	}

      if (enabled)
	{
	  rescan_symbols();
	  update_leak_labels();
	}
#else /* not HAVE_SYMBOL_FILE */
      printf("No symbol file support.\n");
#endif /* not HAVE_SYMBOL_FILE */
    }
  else
    {
      printf("Unknown object to enable: `%s'.\n", argv[1]);
      return 0;
    }

  return 0;
}

CMD(version, "Print program version information.", NULL)
{
  version();

  return 0;
}


CMD(help, "Print list of commands.", NULL)
{
  if (argc == 1)
    {
      do_cmd_help();
    }
  else
    {
      int i;

      for (i = 1; i < argc; i++)
        do_help_on_cmd(argv[i]);
    }

  return 0;
}


CMD(pwd, "Print current working directory.", NULL)
{
  char *buf = NULL;
  size_t size = 0;

  do
    {
      size += 1024;
      buf = gnu_xrealloc(buf, size);
    }
  while (getcwd(buf, size) == NULL);

  printf("%s\n", buf);
  gnu_xfree(buf);

  return 0;
}


CMD(cd, "Change current working directory to DIRECTORY.", NULL)
{
  if (chdir(argv[1]) < 0)
    printf("Changing working directory failed: %s\n", strerror(errno));

  return 0;
}

CMD(chroot,
    "Change root directory to DIRECTORY.",
    "\
If the DIRECTORY is not specified, clears the root directory specification.\n")
{
  if (argc == 1)
    {
      gnu_xfree(root_dir);
      root_dir = NULL;
    }
  else
    {
      root_dir = gnu_xstrdup(argv[1]);
    }

  return 0;
}

typedef enum
{
  DATA_FMT_HEXL,
  DATA_FMT_DEC
} DataFmt;

CMD(data,
    "Show the beginning of the leaked data block.",
    "\
Possible data formatting options are:\n\
  - /x  print data in hexl format (default)\n\
  - /d  print data in decimal format\n")
{
  DataFmt fmt = DATA_FMT_HEXL;
  unsigned char *data;
  size_t data_len;
  size_t i, j, jmax;

  NEED_LEAKS();

  if (argc == 2)
    {
      if (strcmp(argv[1], "/x") == 0)
	fmt = DATA_FMT_HEXL;
      else if (strcmp(argv[1], "/d") == 0)
	fmt = DATA_FMT_DEC;
      else
	{
	  printf("Unknown data format `%s'.\n", argv[1]);
	  return 0;
	}
    }

  data = current_leak->data;
  data_len = current_leak->data_len;

  switch (fmt)
    {
    case DATA_FMT_HEXL:
      for (i = 0; i < data_len; i += 16)
	{
	  printf("%08x: ", i);

	  jmax = data_len - i;
	  if (jmax > 16)
	    jmax = 16;

	  for (j = 0; j < jmax; j++)
	    {
	      if ((j % 2) == 1)
		printf("%02x ", (unsigned char) data[i + j]);
	      else
		printf("%02x", (unsigned char) data[i + j]);
	    }
	  for (; j < 16; j++)
	    {
	      if ((j % 2) == 1)
		printf("   ");
	      else
		printf("  ");
	    }

	  printf(" ");

	  for (j = 0; j < jmax; j++)
	    {
	      int ch = data[i + j];

	      if (ch < 32 || ch >= 127)
		ch = '.';
	      printf("%c", ch);
	    }
	  printf("\n");
	}
      break;

    case DATA_FMT_DEC:
      for (i = 0; i < data_len; i += 8)
	{
	  printf("%8x: ", i);

	  jmax = data_len - i;
	  if (jmax > 8)
	    jmax = 8;

	  for (j = 0; j < jmax; j++)
	    printf("%3u ", (unsigned char) data[i + j]);

	  for (; j < 8; j++)
	    printf("   ");

	  printf(" ");

	  for (j = 0; j < jmax; j++)
	    {
	      int ch = data[i + j];

	      if (ch < 32 || ch >= 127)
		ch = '.';
	      printf("%c", ch);
	    }
	  printf("\n");
	}
      break;
    }

  return 0;
}


struct
{
  char *name;
  char *alias_of;
  unsigned int min_args;
  unsigned int max_args;
  int (*impl)(int argc, char *argv[]);
  char **synopsis;
  char **help;
  int show_location;
} commands[] =
{
  /*    name,           min,    max,    show location */
  {CMDD(long,           1,      1,      0)},
  {CMDD(short,          1,      1,      0)},

  {CMDD(echo,		1,	-1,	0)},


  {CMDDD("add-symbol-file", add_symbol_file,
                        3,      3,      0)},

  {CMDD(frame,          1,      2,      1)},

  {CMDD(next,           1,      1,      1)},
  {CMDD(previous,       1,      1,      1)},
  {CMDD(fd,		2,      2,      1)},
  {CMDD(leak,           1,      2,      1)},
  {CMDD(leaf,           2,      3,      1)},
  {CMDD(up,             1,      1,      1)},
  {CMDD(down,           1,      1,      1)},

  {CMDD(backtrace,      1,      1,      0)},
  {CMD_ALIAS(bt, backtrace)},

  {CMDD(list,           1,      2,      0)},
  {CMD_ALIAS(ls, list)},

  {CMDD(pc,             2,      2,      0)},
  {CMDD(scan,           2,      2,      0)},
  {CMDD(quit,           1,      1,      0)},

  {CMDD(info,           1,      2,      0)},
  {CMDD(version,        1,      1,      0)},

  {CMDD(sort,           1,      2,      0)},

  {CMDD(dump,           1,      2,      0)},

  {CMDD(group,          3,      -1,     0)},
  {CMDD(ungroup,        2,      -1,     0)},

  {CMDD(enable,         3,      -1,     0)},

  {CMDD(help,           1,      -1,     0)},

  {CMDD(pwd,		1,	1,	0)},
  {CMDD(cd,		2,	2,	0)},
  {CMDD(chroot,		1,	2,	0)},
  {CMDD(data,		1,	2,	0)},

  {NULL, NULL},
};


static void
do_ambiguous_command(char *cmd)
{
  int i;
  int first = 1;

  printf("Ambiguous command \"%s\":", cmd);
  for (i = 0; commands[i].name; i++)
    {
      size_t len = strlen(commands[i].name);
      size_t cmd_len = strlen(cmd);

      if (cmd_len <= len
          && (memcmp(commands[i].name, cmd, cmd_len) == 0))
        {
          if (first)
            first = 0;
          else
            printf(",");

          printf(" %s", commands[i].name);
        }
    }
  printf(".\n");
}


static void
do_cmd_help(void)
{
  int i;

  printf("Available commands are:\n");

  for (i = 0; commands[i].name; i++)
    if (commands[i].alias_of)
      printf("  %-16s\tAlias for command \"%s\"\n",
             commands[i].name, commands[i].alias_of);
    else
      printf("  %-16s\t%s\n", commands[i].name, *commands[i].synopsis);
}


static void
do_help_on_cmd(char *cmd)
{
  int match = find_command(cmd);

  if (match == -1)
    {
      printf("Undefined command: \"%s\".  Try \"help\".\n", cmd);
    }
  else if (match == -2)
    {
      do_ambiguous_command(cmd);
    }
  else
    {
      printf("%s\n", *commands[match].synopsis);
      if (*commands[match].help)
        printf("%s\n", *commands[match].help);
    }
}


static int
find_command(char *name)
{
  int i;
  size_t cmd_len = strlen(name);
  size_t len;
  int match = -1;

  for (i = 0; commands[i].name; i++)
    {
      len = strlen(commands[i].name);
      if (cmd_len <= len
          && memcmp(commands[i].name, name, cmd_len) == 0)
        {
          if (match >= 0)
            return -2;
          else
            match = i;
        }
    }

  if (match >= 0)
    {
      if (commands[match].alias_of)
        return find_command(commands[match].alias_of);
    }

  return match;
}


static GnuBool
do_command(const char *file, int line, char *command)
{
  int argc = 0;
  char **argv = NULL;
  int i;
  int start;
  GnuBool done = FALSE;

  /* Store the name of our input stream. */
  input_file = file;
  input_line = line;

  /* We do not have the command name yet. */
  command_name = NULL;

  /* Tokenize command. */
  i = 0;
  while (1)
    {
      /* Skip leading whitespace. */
      for (; command[i] && ISSPACE(command[i]); i++)
        ;

      if (!command[i])
        break;

      /* Read the word. */
      start = i;
      for (i++; command[i] && !ISSPACE(command[i]); i++)
        ;
      argv = gnu_xrealloc(argv, (argc + 1) * sizeof(*argv));
      argv[argc++] = gnu_xmemdup(command + start, i - start);
    }

  if (argc)
    {
      int match;

      /* Find an unambiguous match. */
      match = find_command(argv[0]);

      if (match == -1)
        {
          message("Undefined command: \"%s\".\n", argv[0]);
        }
      else if (match == -2)
        {
          do_ambiguous_command(argv[0]);
        }
      else
        {
          /* Found a match. */
          if (argc < commands[match].min_args)
            {
              message("Too few arguments for command \"%s\".\n",
                      commands[match].name);
            }
          else if (argc > commands[match].max_args)
            {
              message("Too many arguments for command \"%s\".\n",
                      commands[match].name);
            }
          else
            {
              /* Fix command name. */
              gnu_xfree(argv[0]);
              argv[0] = gnu_xstrdup(commands[match].name);

              command_name = commands[match].name;

              if (verbose >= 2 && input_file)
                message("Executing command.\n");

              if ((*commands[match].impl)(argc, argv))
                done = TRUE;

              last_command = commands[match].impl;

              if (file == NULL && commands[match].show_location)
                print_location();
            }
        }
    }

  /* Free command. */
  for (i = 0; i < argc; i++)
    gnu_xfree(argv[i]);
  gnu_xfree(argv);
  argv = NULL;

  return done;
}


static void
memory_leak_check_shell(void)
{
  char prev_command[512];
  int prev_command_valid = 0;
  char command[512];

  leak_info();
  print_location();

  while (1)
    {
      int i;

      printf("(stacktrace) ");
      fflush(stdout);

      if (!fgets(command, sizeof(command), stdin))
        break;

      /* Is this an empty line? */
      for (i = 0; command[i] && ISSPACE(command[i]); i++)
        ;
      if (!command[i])
        {
          /* Yes it was. */
          if (prev_command_valid)
            /* Reuse last command. */
            memcpy(command, prev_command, sizeof(command));
          else
            /* Read next command. */
            continue;
        }
      else
        {
          /* No it was not.  Now we have a valid previous command. */
          memcpy(prev_command, command, sizeof(prev_command));
          prev_command_valid = 1;
        }

      if (do_command(NULL, 0, command))
        break;
    }
}


/************************** Processing init files ***************************/

static GnuBool
try_init_file(const char *path)
{
  struct stat stat_struct;
  FILE *fp;
  char command[512];
  int line = 0;

  /* Check if the file exists. */
  if (stat(path, &stat_struct) < 0)
    return FALSE;

  if (verbose)
    message("Loading init file `%s'.\n", path);

  /* It exists. */
  fp = fopen(path, "r");
  if (fp == NULL)
    {
      fprintf(stderr, "%s: Could not open init file `%s': %s\n",
              optctx.program, path, strerror(errno));
      return TRUE;
    }

  /* Process the init file. */
  while (1)
    {
      int i;

      if (!fgets(command, sizeof(command), fp))
        break;

      line++;

      /* Is this an empty line or a comment? */
      for (i = 0; command[i] && ISSPACE(command[i]); i++)
        ;
      if (!command[i])
        /* An empty line. */
        continue;
      if (command[i] == '#')
        /* A comment. */
        continue;

      /* Process the command. */
      if (do_command(path, line, command))
        break;
    }

  fclose(fp);

  return TRUE;
}

static void
do_read_init_file(void)
{
  char *env;
  char *path;

  if (try_init_file(INIT_FILE_NAME))
    /* File found and processed. */
    return;

  /* Try user's home directory. */
  env = getenv("HOME");
  if (env == NULL)
    /* No home directory specified.  We are done. */
    return;

  path = gnu_xmalloc(strlen(env) + 1 + strlen(INIT_FILE_NAME) + 1);
  path[0] = '\0';

  strcat(path, env);
  strcat(path, "/");
  strcat(path, INIT_FILE_NAME);

  try_init_file(path);
  gnu_xfree(path);
}
