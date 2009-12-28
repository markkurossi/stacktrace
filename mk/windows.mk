
cc = $(CC) -c $(DEFS) $(3) $(PICFLAGS) $(CPPFLAGS) $(CFLAGS) /Fo$(1) $(2)
ld = $(CC) $(LDFLAGS) /Fe$(1) $(2) $(LIBS) $(3) $(LD2FLAGS) $(4)

O = obj
A = lib
EXE = .exe
PS = ;

# Clean path.
pathclean := $(subst \,/,$(subst ;, ,$(subst $(space),_space_,$(PATH))))

# Function to find argument program from path.
pathprog = $(subst _space_, ,$(firstword $(foreach d,$(pathclean),$(subst $(space),_space_,$(wildcard $(subst _space_,\ ,$(d))/$(1).exe)))))

CC = $(call pathprog,cl)
CPP = $(call pathprog,cl)
