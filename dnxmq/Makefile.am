EXTRA_DIST = fakeworker.py zmq3compat.h mqexec.init mqbroker.init mqexec.h

sbin_PROGRAMS = mqexec mqbroker

mqexec_SOURCES = mqexec.c kickoff.c parsesocket.c children.c filters.c heartbeats.c
mqexec_LDADD = -ljansson -lev @libpcre_LIBS@ @jansson_LIBS@ @libev_LIBS@ @libzmq_LIBS@
mqexec_CFLAGS = @libpcre_CFLAGS@ @jansson_CFLAGS@ @libev_CFLAGS@ @libzmq_CFLAGS@

mqbroker_SOURCES = mqbroker.c
mqbroker_LDADD = @libzmq_LIBS@ @jansson_LIBS@
mqbroker_CFLAGS = @libzmq_CFLAGS@ @jansson_CFLAGS@
