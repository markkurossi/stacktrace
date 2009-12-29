#
# GNUmakefile
#
# Author: Markku Rossi <mtr@iki.fi>
#
# Copyright (c) 2003-2009 Markku Rossi.
#               All rights reserved.
#
# GNU makefile for the stacktrace program.  Since it seems to be too
# hard to get this directory to build during the normal compilation,
# this GNU makefile can be used for self-contained build.
#

# Some magics.
empty :=
space := $(empty) $(empty)

# Include configure definition.
include config.mk

# Include platform specific make rules.
include mk/$(os).mk

# If you can't find libbfd.a from your system, download and compile
# gdb and set its build location here.
GDB := /home/mtr/Desktop/gdb-6.6

ALL_TARGETS := stacktrace$(EXE)

DISTFILES := COPYING LICENSE README TODO GNUmakefile configure	\
configure.bat $(wildcard include/*.h) $(wildcard mk/*.mk)	\
runmallocdebug stacktrace.el pistacktrace_none.c

ifeq ($(os),unix)

DEFS += -DHAVE_UNISTD_H=1 -DHAVE_STRINGS_H=1

DEFS += -DHAVE_BFD_H=1
LDFLAGS := -L/usr/local/lib
LIBS := -lbfd -liberty

SO_CFLAGS = -fPIC -DPIC
SO_LDFLAGS = -shared
SO_LIBS =

ALL_TARGETS += libmallocdebug.so

ifeq ($(uname),Linux)
debug := 1
LDFLAGS += -L$(GDB)/bfd -L$(GDB)/libiberty
override CPPFLAGS += -I$(GDB)/bfd -I$(GDB)/include
SO_LIBS += -ldl
endif

ifeq ($(uname),NetBSD)
debug := 1
override CPPFLAGS += -Iinclude
endif

ifeq ($(uname),FreeBSD)
debug := 1
LDFLAGS += -L$(GDB)/bfd -L$(GDB)/libiberty
override CPPFLAGS += -I$(GDB)/bfd -I$(GDB)/include
#override CPPFLAGS += -Iinclude
LIBS += -lintl
endif

override CPPFLAGS += -I/usr/local/include

ifeq ($(debug),1)

ifeq ($(GCC),1)

CFLAGS = -g -Wall
LDFLAGS += -g

else

CFLAGS = -g
LDFLAGS += -g

endif

endif

else # not unix


CFLAGS=/nologo /W2 /Ox
LDFLAGS=/nologo
LD2FLAGS=/link

endif

srcs = stacktrace.c gnudebug.h gnudebug.c gnuglob.h gnuglob.c	\
gnuincludes.h gnumalloc.h gnumalloc.c pigetopt.h pigetopt.c
objs = $(patsubst %.c,%.$(O),$(filter %.c,$(srcs)))

DISTFILES += $(srcs)

CLEANFILES := $(objs) stacktrace$(EXE) core *.core core.*

all: $(ALL_TARGETS)

# Creating objects from C source files.
%.$(O) : %.c
	$(call cc,$@,$<)

stacktrace$(EXE): $(objs)
	$(call ld,$@,$+)

mallocdebug_so_src = piconf.h pifatal.h pifatal.c piincludes.h	\
pimalloc.h pimalloc.c pistacktrace.h malloc_wrappers.c pistacktrace_x86_gcc.c

DISTFILES += $(mallocdebug_so_src)

mallocdebug_so_objs = $(patsubst %.c,%.$(O),$(filter %.c,$(mallocdebug_so_src)))

CLEANFILES += $(mallocdebug_so_objs) libmallocdebug.so

$(mallocdebug_so_objs): %.$(O): %.c
	$(CC) $(CFLAGS) $(SO_CFLAGS) -c $< -o $@

libmallocdebug.so: $(mallocdebug_so_objs)
	$(CC) $(LDFLAGS) $(SO_LDFLAGS) -o $@ $^ $(SO_LIBS)

.PHONY: .clean

clean:
	$(RM) $(CLEANFILES)


# Distribution making

PACKAGE_NAME = stacktrace
PACKAGE_VERSION = 1.0

empty :=
space := $(empty) $(empty)

patch_level = $(patsubst patch-%,%,$(shell tla logs | tail -1))
distpackagedir_data = $(PACKAGE_NAME) $(PACKAGE_VERSION).$(patch_level)
distpackagedir = $(subst $(space),-,$(distpackagedir_data))

distfiles = $(sort $(subst $$,\$$,$(DISTFILES)))

distdirectories = $(sort $(foreach f,$(distfiles),$(dir $(f))))

dist:
	@echo "Making $(distpackagedir).tar.gz..."
	@rm -rf $(distpackagedir)
	@echo "Making directories..."
	@for f in $(distdirectories); do \
	  ./mkinstalldirs $(distpackagedir)/$$f; \
	done
	@echo "Symlinking files..."
	@for f in $(distfiles); do \
	  ln -s `pwd`/$$f $(distpackagedir)/$$f; \
	done
	@echo "Building package..."
	@tar chzf  $(distpackagedir).tar.gz $(distpackagedir)
	-@zip -q -r $(distpackagedir).zip $(distpackagedir)
	@echo "Cleaning up..."
	@rm -rf $(distpackagedir)
	@echo "Distribution $(distpackagedir).{tar.gz,zip} is ready:"
	-@ls -l $(distpackagedir).tar.gz
	-@ls -l $(distpackagedir).zip

push:
	git push origin master
