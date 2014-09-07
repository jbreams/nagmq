#!/usr/bin/env python

from distutils.core import setup

setup(name="nagmq-collector",
	version="0.9",
	description="NagMQ to MongoDB connector daemon",
	author="Jonathan Reams",
	author_email="jbreams@gmail.com",
	url="https://github.com/jbreams/nagmq",
	py_modules=['collector'],
	scripts=['collectord'],
	requires=['zmq', 'pymongo', 'simplejson', 'yaml']
)