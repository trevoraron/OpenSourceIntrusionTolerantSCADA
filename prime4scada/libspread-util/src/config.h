/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.in by autoheader.  */

#ifndef _CONFIG_H
#define _CONFIG_H


/* Building on a Windows OS Platform */
/* #undef ARCH_PC_WIN95 */

/* Platform supports sendmsg scatter/gather using accrights structure */
/* #undef ARCH_SCATTER_ACCRIGHTS */

/* Platform supports sendmsg scatter/gather using control structure */
#define ARCH_SCATTER_CONTROL 1

/* Platform does not support scatter/gather sendmsg */
/* #undef ARCH_SCATTER_NONE */

/* Define if your snprintf is busted */
/* #undef BROKEN_SNPRINTF */

/* Disable lookups of function names using dladdr */
/* #undef DISABLE_FUNCTION_NAME_LOOKUP */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `bcopy' function. */
#define HAVE_BCOPY 1

/* Have clock_gettime(CLOCK_MONOTONIC, ...)! */
#define HAVE_CLOCK_GETTIME_CLOCK_MONOTONIC 1

/* clock_t type */
#define HAVE_CLOCK_T 1

/* dladdr function */
#define HAVE_DLADDR 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* int64_t type */
#define HAVE_INT64_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* various intxx_t types */
#define HAVE_INTXX_T 1

/* Define to 1 if you have the `m' library (-lm). */
#define HAVE_LIBM 1

/* Define to 1 if you have the `nsl' library (-lnsl). */
#define HAVE_LIBNSL 1

/* Define to 1 if you have the `posix4' library (-lposix4). */
/* #undef HAVE_LIBPOSIX4 */

/* Define to 1 if you have the `pthread' library (-lpthread). */
#define HAVE_LIBPTHREAD 1

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `thread' library (-lthread). */
/* #undef HAVE_LIBTHREAD */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `lrand48' function. */
#define HAVE_LRAND48 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* pid_t type */
#define HAVE_PID_T 1

/* Define to 1 if you have the <process.h> header file. */
/* #undef HAVE_PROCESS_H */

/* Define to 1 if you have the `pthread_atfork' function. */
#define HAVE_PTHREAD_ATFORK 1

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* sa_family_t type */
#define HAVE_SA_FAMILY_T 1

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* sockaddr_in type has sin_len field */
/* #undef HAVE_SIN_LEN_IN_SOCKADDR_IN */

/* size_t type */
#define HAVE_SIZE_T 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* socklen_t type */
#define HAVE_SOCKLEN_T 1

/* struct sockopt_len_t */
/* #undef HAVE_SOCKOPT_LEN_T */

/* signed size_t type */
#define HAVE_SSIZE_T 1

/* struct sockaddr_storage has ss_family */
#define HAVE_SS_FAMILY_IN_SS 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* struct sockaddr type */
#define HAVE_STRUCT_ADDRINFO 1

/* struct in6_addr type */
#define HAVE_STRUCT_IN6_ADDR 1

/* struct sockaddr_in6 type */
#define HAVE_STRUCT_SOCKADDR_IN6 1

/* struct sockaddr_storage type */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* struct timeval */
#define HAVE_STRUCT_TIMEVAL 1

/* struct timezone */
#define HAVE_STRUCT_TIMEZONE 1

/* sockaddr_un type has sun_len field */
/* #undef HAVE_SUN_LEN_IN_SOCKADDR_UN */

/* sys_errlist structure */
#define HAVE_SYS_ERRLIST 1

/* Define to 1 if you have the <sys/filio.h> header file. */
/* #undef HAVE_SYS_FILIO_H */

/* Define to 1 if you have the <sys/inttypes.h> header file. */
/* #undef HAVE_SYS_INTTYPES_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* sys_nerr function */
#define HAVE_SYS_NERR 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/timeb.h> header file. */
#define HAVE_SYS_TIMEB_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the `time' function. */
#define HAVE_TIME 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* various unsigned intxx_t types */
/* #undef HAVE_UINTXX_T */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* unsigned int type u_int */
#define HAVE_U_INT 1

/* unsigned int64_t */
#define HAVE_U_INT64_T 1

/* various unsigned intxx_t types */
#define HAVE_U_INTXX_T 1

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if you have the <winsock.h> header file. */
/* #undef HAVE_WINSOCK_H */

/* Define if libc defines __progname */
#define HAVE___PROGNAME 1

/* struct sockaddr_storage has __ss_family field */
/* #undef HAVE___SS_FAMILY_IN_SS */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "Spread_Util"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "Spread_Util 4.2.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "spread_util"

/* Define to the version of this package. */
#define PACKAGE_VERSION "4.2.0"

/* The size of `char', as computed by sizeof. */
#define SIZEOF_CHAR 1

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long int', as computed by sizeof. */
#define SIZEOF_LONG_INT 8

/* The size of `long long int', as computed by sizeof. */
#define SIZEOF_LONG_LONG_INT 8

/* The size of `short int', as computed by sizeof. */
#define SIZEOF_SHORT_INT 2

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Enable Threaded Alarm code to move IO to separate thread */
/* #undef USE_THREADED_ALARM */

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel and VAX). */
#if defined __BIG_ENDIAN__
# define WORDS_BIGENDIAN 1
#elif ! defined __LITTLE_ENDIAN__
/* # undef WORDS_BIGENDIAN */
#endif

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

#include "defines.h"

#endif /* _CONFIG_H */

