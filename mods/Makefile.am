
EXTRA_DIST = json.h naginclude/*.h
pkglib_LTLIBRARIES = nagmq.la
nagmq_la_SOURCES = nagmq_pull.c nagmq_req.c nagmq_pub.c common.c json.c
nagmq_la_LDFLAGS = -module -fPIC -pipe
nagmq_la_LIBADD = ../jansson/src/libjansson.la
nagmq_la_CFLAGS = -I../jansson/src
