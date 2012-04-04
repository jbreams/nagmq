sbin_PROGRAMS = mqexec

mqexec_SOURCES = mqexec.c ../libev/ev.c
mqexec_LDADD = ../jansson/src/libjansson.la @PCRE_LIBS@
mqexec_CFLAGS = -I../jansson/src @PCRE_HEADERS@
