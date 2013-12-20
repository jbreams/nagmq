EXTRA_DIST = fakeworker.py zmq3compat.h mqexec.init mqbroker.init

sbin_PROGRAMS = mqexec mqbroker

mqexec_SOURCES = mqexec.c
mqexec_LDADD = -ljansson -lev @PCRE_LIBS@
mqexec_CFLAGS = @PCRE_HEADERS@

mqbroker_SOURCES = mqbroker.c
mqbroker_LDADD = -ljansson
