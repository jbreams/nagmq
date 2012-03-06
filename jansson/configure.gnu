#!/bin/sh

ARGS=""
for i in $*
do
	case $1 in
		--srcdir=*)
			srcdir=`expr "x$1" : 'x[^=]*=\(.*\)'`
			;;
		--prefix=*)
			prefix=`expr "x$1" : 'x[^=]*=\(.*\)'`
			;;
		*)
			ARGS="$ARGS $1"
	esac
	shift 1
done

$srcdir/configure --prefix=$prefix --disable-shared --with-pic

