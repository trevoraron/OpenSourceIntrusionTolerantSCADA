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

#ifndef stderror_h_2000_05_15_14_04_16_jschultz_at_cnds_jhu_edu
#define stderror_h_2000_05_15_14_04_16_jschultz_at_cnds_jhu_edu

#include <errno.h>
#include <stdio.h>

#include <stdutil/stddefines.h>

#ifdef __cplusplus
extern "C" {
#endif

/* stderr error routines */

#ifndef STDERR_MAX_ERR_MSG_LEN 
/* NOTE: redefining this variable only has an effect at compile time of the stdutil LIBRARY; not app. code */
#  define STDERR_MAX_ERR_MSG_LEN 8192
#endif

int  stderr_msg(const char *fmt, ...);
int  stderr_ret(const char *fmt, ...);
void stderr_quit(const char *fmt, ...);
void stderr_abort(const char *fmt, ...);
void stderr_sys(const char *fmt, ...);
void stderr_dump(const char *fmt, ...);

STDINLINE const char *stderr_strerr(stdcode code);

/* error macros */

#define STDEXCEPTION(x) stderr_abort("STDEXCEPTION: File: %s; Line: %d: %s", __FILE__, __LINE__, #x)

#if defined(STDSAFETY_CHECKS)
#  define STDSAFETY_CHECK(x) { if (!(x)) { STDEXCEPTION(safety check (x) failed); } }
#else
#  define STDSAFETY_CHECK(x) 
#endif

#if defined(STDBOUNDS_CHECKS)
#  define STDBOUNDS_CHECK(x) { if (!(x)) { STDEXCEPTION(bounds check (x) failed); } }
#else
#  define STDBOUNDS_CHECK(x)
#endif

#define STDESUCCESS 0
#define STDEOF EOF

#if defined(EUNKNOWN)
#  define STDEUNKNOWN EUNKNOWN
#else
#  define STDEUNKNOWN 500
#endif

#if defined(EINVAL)
#  define STDEINVAL EINVAL
#else
#  define STDEINVAL 501
#endif

#if defined(ENOMEM)
#  define STDENOMEM ENOMEM
#else
#  define STDENOMEM 502
#endif

#if defined(EACCES)
#  define STDEACCES EACCES
#else
#  define STDEACCES 503
#endif

#if defined(EBUSY)
#  define STDEBUSY EBUSY
#else
#  define STDEBUSY 504
#endif

#if defined(EPERM)
#  define STDEPERM EPERM
#else
#  define STDEPERM 505
#endif

#if defined(ENOSYS)
#  define STDENOSYS ENOSYS
#else
#  define STDENOSYS 506
#endif

#if defined(EINTR)
#  define STDEINTR EINTR
#else
#  define STDEINTR 507
#endif

#ifdef __cplusplus
}
#endif

#endif
