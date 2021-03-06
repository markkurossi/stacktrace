Stacktrace
==========

The stacktrace program maps program counter values into corresponding
source files lines.  The program implements both interactive memory
leak check shell and a batch-mode leak dump annotator.  Stacktrace
uses the GNU Binary File Descriptor Library.  You have to have it
installed on your machine before you can compile this program.
Normally the library is installed but the header file is missing.  The
needed components are:

	bfd.h
	ansidecl.h
	libbfd.{so,a}

On Ubuntu Linux you can install the bfd headers by installing the
"binutils-dev" package:

	% sudo apt-get install binutils-dev

If nothing else works, the stacktrace package has one old copy of the
header files in the "include" subdirectory.  These are for NetBSD/x386
platform and might not work on different platforms.

The file "stacktrace.el" contains an Emacs GUD (Grand Unified
Debugger) back-end for the stacktrace program.  You can enable Emacs'
stacktrace integration by copying the "stacktrace.el" into a directory
that is in the Emacs' `load-path' and by adding the following line
into your ".emacs" file:

	(load "stacktrace" t t)

After this, you can used stacktrace from your Emacs as easily as you
can use gdb:

	M-x stacktrace<Return>PROGRAM stacktrace.log<Return>

// Markku Rossi

mtr@iki.fi
http://www.iki.fi/mtr/
