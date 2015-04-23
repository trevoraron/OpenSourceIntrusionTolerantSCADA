/* Copyright (c) 2000-2005, The Johns Hopkins University
 * All rights reserved.
 *
 * The contents of this file are subject to a license (the ``License'')
 * that is the exact equivalent of the BSD license as of July 23, 1999. 
 * You may not use this file except in compliance with the License. The
 * specific language governing the rights and limitations of the License
 * can be found in the file ``STDUTIL_LICENSE'' found in this 
 * distribution.
 *
 * Software distributed under the License is distributed on an AS IS 
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. 
 *
 * The Original Software is:
 *     The Stdutil Library
 * 
 * Contributors:
 *     Creator - John Lane Schultz (jschultz@cnds.jhu.edu)
 *     The Center for Networking and Distributed Systems
 *         (CNDS - http://www.cnds.jhu.edu)
 */ 

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <stdutil/stddefines.h>
#include <stdutil/stderror.h>

/************************************************************************************************
 * stderr_doit: Print a message to stderr and flush it.  If errnoflag
 * is non-zero, also print error msg from errno.  Return # of
 * characters written.
 *
 * NOTE: I'd prefer to use snprintf and vsnprintf but they aren't part of C89.
 ***********************************************************************************************/

STDINLINE static int stderr_doit(int errno_copy, const char *fmt, va_list ap) 
{
  char buf[STDERR_MAX_ERR_MSG_LEN + 1];
  int  ret1;
  int  ret2 = 0;

  ret1      = vsprintf(buf, fmt, ap);  /* write the msg */
  ret1      = STDMAX(ret1, 0);         /* zero out any error */
  buf[ret1] = 0;                       /* ensure termination */

  if (errno_copy != 0) {
    ret2             = sprintf(buf + ret1, ": %s", strerror(errno_copy));   /* write errno msg */
    ret2             = STDMAX(ret2, 0);                                     /* zero out any error */
    buf[ret1 + ret2] = 0;                                                   /* ensure termination */
  }

  fprintf(stderr, "%s\r\n", buf);
  fflush(stderr);

  return ret1 + ret2;
}

/************************************************************************************************
 * stderr_msg: Nonfatal error unrelated to a system call. Print a
 * message and return.
 ***********************************************************************************************/

int stderr_msg(const char *fmt, ...) 
{
  int     ret;
  va_list ap;

  va_start(ap, fmt);
  ret = stderr_doit(0, fmt, ap);
  va_end(ap);

  return ret;
}

/************************************************************************************************
 * stderr_ret: Nonfatal error related to a system call. Print a
 * message and return.
 ***********************************************************************************************/

int stderr_ret(const char *fmt, ...) 
{
  int     ret;
  va_list ap;

  va_start(ap, fmt);
  ret = stderr_doit(errno, fmt, ap);
  va_end(ap);

  return ret;
}

/************************************************************************************************
 * stderr_quit: Fatal error unrelated to a system call. Print a
 * message and terminate.
 ***********************************************************************************************/

void stderr_quit(const char *fmt, ...) 
{
  va_list ap;

  va_start(ap, fmt);
  stderr_doit(0, fmt, ap);
  va_end(ap);
  exit(-1);
}

/************************************************************************************************
 * stderr_abort: Fatal error unrelated to a system call. Print a
 * message and abort.
 ***********************************************************************************************/

void stderr_abort(const char *fmt, ...) 
{
  va_list ap;

  va_start(ap, fmt);
  stderr_doit(0, fmt, ap);
  va_end(ap);
  abort();
}

/************************************************************************************************
 * stderr_sys: Fatal error related to a system call. Print a message
 * and terminate.
 ***********************************************************************************************/

void stderr_sys(const char *fmt, ...) 
{
  int     errno_cpy = errno;
  va_list ap;

  va_start(ap, fmt);
  stderr_doit(errno_cpy, fmt, ap);
  va_end(ap);
  exit(errno_cpy != 0 ? errno_cpy : -1);
}

/************************************************************************************************
 * stderr_dump: Fatal error related to a system call. Print a message
 * and abort.
 ***********************************************************************************************/

void stderr_dump(const char *fmt, ...) 
{
  va_list ap;

  va_start(ap, fmt);
  stderr_doit(errno, fmt, ap);
  va_end(ap);
  abort();
}

/************************************************************************************************
 * stderr_strerr: Returns a constant string in response to a StdUtil
 * error code.  Some StdUtil fcns can return system specific codes.
 * In that case this fcn will return a "Unknown Error Code (system
 * error code)" string and you should consult your system specific
 * error lookup service.
 ***********************************************************************************************/

STDINLINE const char *stderr_strerr(stdcode code)
{
  const char * ret;

  switch (code) {
  case STDEUNKNOWN:
    ret = "Unknown Error";
    break;

  case STDEINVAL:
    ret = "Invalid Argument";
    break;

  case STDENOMEM:
    ret = "Memory Allocation Failed";
    break;

  case STDEACCES:
    ret = "Permission Denied";
    break;

  case STDEBUSY:
    ret = "Resource Busy";
    break;

  case STDEPERM:
    ret = "Operation Not Permitted";
    break;

  case STDENOSYS:
    ret = "Functionality Not Implemented";
    break;

  case STDEINTR:
    ret = "Operation Interrupted";
    break;

  default:
    ret = "Unknown Error Code (system error code)";
    break;
  }

  return ret;
}
