AC_PREREQ([2.60])
AC_INIT([nagmq], [1.3.1], [nagmq@googlegroups.com])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_CONFIG_SRCDIR([mods/nagmq_pub.c])
AC_CONFIG_HEADERS([mods/config.h libev/config.h dnxmq/config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_WITH([pcre-config],
	[AC_HELP_STRING([--with-pcre-config],
		[Path to PCRE configuration for mqexec filtering])],
	[pcre_config_prog=$withval])
AC_PATH_PROG(PCRE_CONFIG, [pcre-config], $pcre_config_prog)

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_LIBTOOL

AC_CHECK_LIB([zmq], [zmq_socket], [],
	[AC_MSG_FAILURE([Could not find usable ZMQ library])], [])

AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h float.h pthread.h signal.h stdarg.h \
	sys/types.h syslog.h time.h zmq.h])

AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([malloc realloc memset free strdup])
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD

m4_include([libev/libev.m4])
if test "x$PCRE_CONFIG" != "x"; then
	CFLAGS_SAVE=$CFLAGS
	LIBS_SAVE=$LIBS
	CFLAGS="$CFLAGS $($PCRE_CONFIG --cflags)"
	LIBS="$LIBS $($PCRE_CONFIG --libs)"
	AC_CHECK_HEADER([pcre.h], [],
		AC_MSG_FAILURE([PCRE was enabled but headers weren't found]), [])
	AC_CHECK_LIB([pcre], [pcre_compile], [],
		AC_MSG_FAILURE([PCRE was enabled but libraries weren't found]), [])
	CFLAGS=$CFLAGS_SAVE
	LIBS=$LIBS_SAVE
	AC_SUBST([PCRE_HEADERS], $($PCRE_CONFIG --cflags))
	AC_SUBST([PCRE_LIBS], $($PCRE_CONFIG --libs))
	AC_DEFINE([HAVE_PCRE], [], [PCRE Libraries are installed])
fi

WITHHEADERS="no"
AC_ARG_WITH([icinga-headers],
	[AC_HELP_STRING([--with-icinga-headers=DIR],
		[Path to header files for Icinga])],
	[
		WITHHEADERS="-I$withval"
		AC_DEFINE([HAVE_ICINGA], [], [Compiling against Icinga])
	],
	[]
)

AC_ARG_WITH([nagios3-headers],
	[AC_HELP_STRING([--with-nagios3-headers=DIR],
		[Path to header files for Nagios])],
	[
		WITHEADERS="-I$withval"
		AC_DEFINE([HAVE_NAGIOS3], [], [Compiling against Nagios 3])
	],
	[]
)

AC_ARG_WITH([nagios4-src],
	[AC_HELP_STRING([--with-nagios4-src=DIR],
		[Path to source files for Nagios 4])],
	[
		WITHHEADERS="-I$withval/include -I$withval"
		AC_DEFINE([HAVE_NAGIOS4], [], [Compiling against Nagios 4])
	],
	[]
)

AC_ARG_WITH([naemon-src],
	[AC_HELP_STRING([--with-naemon-src=DIR],
		[Path to source files for Naemon])],
	[
		WITHHEADERS="-I$withval"
		# For right now these are one and the same
		AC_DEFINE([HAVE_NAGIOS4], [], [Compiling against Nagios 4.x])
		AC_DEFINE([HAVE_NAEMON], [], [Compiling against Naemon])
	],
	[]
)

CFLAGS_BAK=$CFLAGS
if test "$WITHHEADERS" = "no"; then
	WITHHEADERS="-I./mods/naginclude"
	CFLAGS="$CFLAGS $WITHHEADERS"
fi

AC_SUBST([WITHHEADERS])

AC_CHECK_DECL([add_check_result_to_list(check_result **, check_result *)],
	AC_DEFINE([HAVE_ADD_CHECK_RESULT_TWO], [], [Two parameter add_check_result_to_list]),
	[], [
AC_INCLUDES_DEFAULT
#ifdef HAVE_ICINGA
#include <icinga.h>
#else
#include <nagios.h>
#endif
#define __cplusplus])
AC_CHECK_DECL([add_check_result_to_list(check_result *)],
	AC_DEFINE([HAVE_ADD_CHECK_RESULT_ONE], [], [One parameter add_check_result_to_list]),
	[], [
AC_INCLUDES_DEFAULT
#ifdef HAVE_ICINGA
#include <icinga.h>
#else
#include <nagios.h>
#endif
#define __cplusplus])
AC_CHECK_DECL([delete_downtime_by_hostname_service_description_start_time_comment],
	AC_DEFINE([HAVE_DELETE_DOWNTIME_LONGNAME], [], [Have the really really long function name for deleting downtimes]),
	[], [#include <downtime.h>])
CFLAGS=$CFLAGS_BAK

AC_CONFIG_FILES([Makefile mods/Makefile dnxmq/Makefile libev/Makefile])
AC_CONFIG_SUBDIRS([jansson])
AC_OUTPUT
