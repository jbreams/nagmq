ACLOCAL_AMFLAGS = -I ../m4
EXTRA_DIST = json.h common.h
pkglib_LTLIBRARIES = nagmq.la
nagmq_la_SOURCES = nagmq_pull.c nagmq_pub.c common.c jsonemitter.c \
	jsonparser.c getsock.c zapauth.c socketstatus.c
nagmq_la_LDFLAGS = -module -fPIC -pipe
nagmq_la_LIBADD = @libzmq_LIBS@ @jansson_LIBS@
nagmq_la_CFLAGS = @WITHHEADERS@ @libzmq_CFLAGS@ @jansson_CFLAGS@  -Werror=implicit-function-declaration
