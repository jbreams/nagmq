#!/usr/bin/python

# This script assumes mqexec has been compiled with -DTEST

import zmq, json, time

payload = '{ "host_name": "fakehost", "service_description": "fakeservice", "check_type": 0, "check_options": 0, "scheduled_check": 1, "reschedule_check": 1, "latency": 0.89600, "timeout": 60, "type": "service_check_initiate", "command_name": "echo", "command_args": "\"test test test\"", "command_line": "/bin/echo \"test test test\"" }'

ctx = zmq.Context()
pub = ctx.socket(zmq.PUSH)
pull = ctx.socket(zmq.PULL)

pull.connect("ipc:///tmp/nagmqpull.sock")
pub.connect("ipc:///tmp/nagmq.sock")

for i in range(1, 10):
	pub.send("service_check_initiate", zmq.SNDMORE)
	pub.send(payload)
	time.sleep(0.01)
	print i

for i in range(1, 10):
	ret = pull.recv()
	print i
