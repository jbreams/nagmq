ACLOCAL_AMFLAGS = -I ../m4
EXTRA_DIST = json.h output_hash_raw.c common.h
pkglib_LTLIBRARIES = nagmq.la
nagmq_la_SOURCES = nagmq_pull.c nagmq_req.c nagmq_pub.c common.c jsonemitter.c jsonparser.c
nagmq_la_LDFLAGS = -module -fPIC -pipe
nagmq_la_LIBADD = -ljansson
nagmq_la_CFLAGS = @WITHHEADERS@
