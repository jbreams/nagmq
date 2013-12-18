EXTRA_DIST = fakeworker.py zmq3compat.h

sbin_PROGRAMS = mqexec mqbroker

mqexec_SOURCES = mqexec.c
mqexec_LDADD = -ljansson -lev @PCRE_LIBS@
mqexec_CFLAGS = @PCRE_HEADERS@

mqbroker_SOURCES = mqbroker.c
mqbroker_LDADD = -ljansson
