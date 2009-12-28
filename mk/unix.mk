
cc = $(CC) -c $(DEFS) $(3) $(PICFLAGS) $(CPPFLAGS) $(CFLAGS) -o $(1) $(2)
ld = $(CC) $(LDFLAGS) -o $(1) $(2) $(LIBS) $(3)

O = o
A = a
EXE =
PS = :

pathprog = $(firstword $(foreach d,$(subst :, ,$(PATH)),$(wildcard $(d)/$(1))))

CC := $(call pathprog,gcc)
ifeq ($(CC),)
CC := $(call pathprog,cc)
else
GCC := 1
endif
