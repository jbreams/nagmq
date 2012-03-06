AC_PREREQ([2.58])
AC_INIT([nagmq], [1.0], [jbreams@gmail.com])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([mods/nagmq_pub.c])
AC_CONFIG_HEADERS([mods/config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_WITH([zmq-headers],
	[AC_HELP_STRING([--with-zmq-headers],
		[Override default path to ZMQ headers])],
	[]
	[with_zmq_headers=default])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_LIBTOOL

AC_CHECK_LIB([zmq], [zmq_socket], [],
	[AC_MSG_FAILURE([Could not find usable ZMQ library])], [])
AC_CHECK_LIB([pthread], [pthread_create],[],
	[AC_MSG_FAILURE([Could not find pthread_create])], [])

AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h fcntl.h float.h pthread.h signal.h stdarg.h \
	sys/types.h syslog.h time.h zmq.h])

AC_TYPE_SIZE_T
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([malloc realloc memset free strdup])
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD

AC_CONFIG_FILES([Makefile mods/Makefile])
AC_CONFIG_SUBDIRS([jansson])
AC_OUTPUT
