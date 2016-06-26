AC_PREREQ([2.60])
AC_INIT([nagmq], [1.6.0], [nagmq@googlegroups.com])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_SRCDIR([mods/nagmq_pub.c])
AC_CONFIG_HEADERS([mods/config.h dnxmq/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O

dnl AM_PROG_AR is needed for some linker stuff
dnl AC_USE_SYSTEM_EXTENSIONS requires autoconf 2.60
m4_ifdef([AC_USE_SYSTEM_EXTENSIONS], [AC_USE_SYSTEM_EXTENSIONS])
dnl AM_PROG_AR requires automake 1.11 (and uses AC_COMPILE_IFELSE which wants AC_USE_SYSTEM_EXTENSIONS)
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_PREREQ([2.2.6])
LT_INIT([disable-static shared])

AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h float.h signal.h stdarg.h \
	sys/types.h syslog.h time.h])

PKG_CHECK_MODULES([libzmq], [libzmq >= 3])
PKG_CHECK_MODULES([jansson], [jansson])
PKG_CHECK_MODULES([libuv], [libuv])
PKG_CHECK_MODULES([libpcre], [libpcre])
AC_CHECK_HEADER([pthread.h], [], AC_MSG_FAILURE([pthread.h not found]), [])
AC_SEARCH_LIBS([pthread_create], [pthread])

AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([memset strdup malloc realloc])
AC_FUNC_STRTOD

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

AC_ARG_WITH([nagios-src],
	[AC_HELP_STRING([--with-nagios-src=DIR],
		[Path to source files for Nagios 4])],
	[
		WITHHEADERS="-I$withval/include -I$withval"
	],
	[
		AC_CHECK_HEADERS([nagios/nagios.h nagios/lib/libnagios.h],
		[
			WITHHEADERS="-I/usr/include/nagios"
		])
	]
)

AC_ARG_WITH([naemon-src],
	[AC_HELP_STRING([--with-naemon-src=DIR],
		[Path to source files for Naemon])],
	[
		WITHHEADERS="-I$withval"
		# For right now these are one and the same
		AC_DEFINE([HAVE_NAEMON], [], [Compiling against Naemon])
	]
)

CFLAGS_BAK=$CFLAGS
if test "$WITHHEADERS" = "no"; then
	AC_MSG_FAILURE([Must supply headers/source to Nagios - see the README requirements section.])
fi

CFLAGS="$WITHHEADERS $CFLAGS"
AC_SUBST([WITHHEADERS])

AC_CHECK_DECL([delete_downtime_by_hostname_service_description_start_time_comment],
	AC_DEFINE([HAVE_DELETE_DOWNTIME_LONGNAME], [], [Have the really really long function name for deleting downtimes]),
	[], [#include <downtime.h>])
AC_CHECK_DECL([shutdown_command_file_worker],
    AC_DEFINE([HAVE_SHUTDOWN_COMMAND_FILE_WORKER], [], [Have shutdown_command_file_worker function]),
    [], [#include <nagios.h>])
CFLAGS=$CFLAGS_BAK

AC_SUBST([libpcre_LIBS])
AC_SUBST([libpcre_CFLAGS])
AC_SUBST([libzmq_LIBS])
AC_SUBST([libzmq_CFLAGS])
AC_SUBST([jansson_LIBS])
AC_SUBST([jansson_CFLAGS])

AC_CONFIG_FILES([Makefile mods/Makefile dnxmq/Makefile])
AC_OUTPUT
