AC_PREREQ([2.60])
AC_INIT([nagmq], [1.4], [nagmq@googlegroups.com])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([mods/nagmq_pub.c])
AC_CONFIG_HEADERS([mods/config.h dnxmq/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_ARG_WITH([pcre-config],
	[AC_HELP_STRING([--with-pcre-config],
		[Path to PCRE configuration for mqexec filtering])],
	[pcre_config_prog=$withval])
AC_PATH_PROG(PCRE_CONFIG, [pcre-config], $pcre_config_prog)

AC_PROG_CC
AM_PROG_CC_C_O
LT_PREREQ([2.2.6])
LT_INIT([disable-static shared])

AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h float.h signal.h stdarg.h \
	sys/types.h syslog.h time.h])

AC_ARG_WITH([zmq-include],
	[AC_HELP_STRING([--with-zmq-include=DIR], [Path to ZeroMQ headers])],
	[
		if test -r "${withval}/zmq.h"; then
			CPPFLAGS="-I${withval} ${CPPFLAGS}"
		else
			AC_MSG_FAILURE([Specified ZMQ header directory, but no headers found])
		fi
	])
AC_ARG_WITH([zmq-lib],
	[AC_HELP_STRING([--with-zmq-lib=DIR], [Path to ZeroMQ library])],
	[
		if test -e "${withval}/libzmq.so"; then
			LDFLAGS="-L${withval} ${LDFLAGS}"
		else
			AC_MSG_FAILURE([Specified ZMQ lib directory, but no library found])
		fi
	])

AC_CHECK_HEADER([zmq.h],
	[
		AC_CHECK_LIB([zmq], [zmq_socket], [],
			[AC_MSG_FAILURE([Could not find usable ZMQ library])])
	],
	[AC_MSG_FAILURE([Could not find ZMQ header])]
)

AC_ARG_WITH([libev-include],
	[AC_HELP_STRING([--with-libev-include=DIR], [Path to libev headers])],
	[
		if test -r "${withval}/ev.h"; then
			CPPFLAGS="-I${withval} ${CPPFLAGS}"
		else
			AC_MSG_FAILURE([Specified libev header directory, but no headers found])
		fi
	])

AC_ARG_WITH([libev-lib],
	[AC_HELP_STRING([--with-libev-lib=DIR], [Path to libev library])],
	[
		for f in ${withval}/libev.{a,so,dylib}; do
			test -r $f && break || f=''
		done
		if test "$f"; then
			LDFLAGS="-L${withval} ${CPPFLAGS}"
		else
			AC_MSG_FAILURE([Specified libev lib directory, but no library found at ${withval}])
		fi
	])

AC_CHECK_HEADER([ev.h],
	[
		AC_SEARCH_LIBS([ev_sleep], [ev], [],
			[AC_MSG_FAILURE([Could not find libev library])])
	],
	[AC_MSG_FAILURE([Could not find libev header])]
)

AC_ARG_WITH([jansson-include],
	[AC_HELP_STRING([--with-jansson-include=DIR], [Path to libjansson headers])],
	[
		if test -r "${withval}/jansson.h"; then
			CPPFLAGS="-I{withval} ${CPPFLAGS}"
		else
			AC_MSG_FAILURE([Specified jansson header directory, but no headers found])
		fi
	])
AC_ARG_WITH([jansson-lib],
	[AC_HELP_STRING([--with-jansson-lib=DIR], [Path to libjansson library])],
	[
		for f in ${withval}/libjansson.{a,so,dylib}; do
			test -r $f && break || f=''
		done
		if test "$f"; then
			LDFLAGS="-L${withval} ${LDFLAGS}"
		else
			AC_MSG_FAILURE([Specified jansson lib directory, but no library found at ${withval}])
		fi
	])

AC_CHECK_HEADER([jansson.h], 
	[
		AC_SEARCH_LIBS([json_loads], [jansson], [], 
			[AC_MSG_FAILURE([Could not find Jansson libraries])])
	], 
	[AC_MSG_FAILURE([jansson.h not found])]
)

AC_CHECK_HEADER([pthread.h], [], AC_MSG_FAILURE([pthread.h not found]), [])
AC_SEARCH_LIBS([pthread_create], [pthread])

AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([memset strdup malloc realloc])
AC_FUNC_STRTOD

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
	[
		AC_CHECK_HEADER([icinga.h],
			[AC_DEFINE([HAVE_ICINGA], [], [Compiling against Icinga])])
	]
)

AC_ARG_WITH([nagios3-headers],
	[AC_HELP_STRING([--with-nagios3-headers=DIR],
		[Path to header files for Nagios])],
	[
		WITHEADERS="-I$withval"
		AC_DEFINE([HAVE_NAGIOS3], [], [Compiling against Nagios 3])
	]
)

AC_ARG_WITH([nagios4-src],
	[AC_HELP_STRING([--with-nagios4-src=DIR],
		[Path to source files for Nagios 4])],
	[
		WITHHEADERS="-I$withval/include -I$withval"
		AC_DEFINE([HAVE_NAGIOS4], [], [Compiling against Nagios 4])
	],
	[
		AC_CHECK_HEADERS([nagios/nagios.h nagios/lib/libnagios.h],
		[
			WITHHEADERS="-I/usr/include/nagios"
			AC_DEFINE([HAVE_NAGIOS4], [], [Compiling against Nagios 4])
		])
	]
)

AC_ARG_WITH([naemon-src],
	[AC_HELP_STRING([--with-naemon-src=DIR],
		[Path to source files for Naemon])],
	[
		WITHHEADERS="-I$withval"
		# For right now these are one and the same
		AC_DEFINE([HAVE_NAGIOS4], [], [Compiling against Nagios 4.x])
		AC_DEFINE([HAVE_NAEMON], [], [Compiling against Naemon])
	]
)

CFLAGS_BAK=$CFLAGS
if test "$WITHHEADERS" = "no"; then
	WITHHEADERS="-I./naginclude"
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

AC_CONFIG_FILES([Makefile mods/Makefile dnxmq/Makefile])
AC_OUTPUT
