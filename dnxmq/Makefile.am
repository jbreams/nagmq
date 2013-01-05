EXTRA_DIST = fakeworker.py zmq3compat.h

sbin_PROGRAMS = mqexec mqbroker

mqexec_SOURCES = mqexec.c ../libev/ev.c
mqexec_LDADD = ../jansson/src/libjansson.la @PCRE_LIBS@
mqexec_CFLAGS = -I../jansson/src @PCRE_HEADERS@

mqbroker_SOURCES = mqbroker.c
mqbroker_LDADD = ../jansson/src/libjansson.la
mqbroker_CFLAGS = -I../jansson/src
