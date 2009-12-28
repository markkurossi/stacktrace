/*
 *
 * pifatal.h
 *
 * Author: Markku Rossi <mtr@iki.fi>
 *
 * Copyright (c) 2003-2005 Markku Rossi.
 *
 * See the LICENSE file for the details on licensing.
 *
 * Reporting fatal errors.
 *
 */

#ifndef PIFATAL_H
#define PIFATAL_H

/* Report a fatal error `fmt', `...' to the user and terminate the
   application.  The function never returns.  If an application calls
   this function, the application will be terminated by this call.
   The exact details of the application termination are platform and
   application issues but it is guaranteed that the program execution
   will be terminated. */
void pi_fatal(const char *fmt, ...);

#endif /* PIFATAL_H */
