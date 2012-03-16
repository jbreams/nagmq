#!/usr/bin/python26

import json, time, zmq

zc = zmq.Context()

workerpull = zc.socket(zmq.PULL)
workerpush = zc.socket(zmq.PUSH)
extsub = zc.socket(zmq.SUB)
extpush = zc.socket(zmq.PUSH)

workerpull.bind("ipc:///tmp/dnxmqpull.sock")
workerpush.bind("ipc:///tmp/dnxmqpush.sock")
extsub.connect("ipc:///tmp/nagmq.sock")
extsub.setsockopt(zmq.SUBSCRIBE, 'host_check_initiate')
extsub.setsockopt(zmq.SUBSCRIBE, 'service_check_initiate')
extpush.connect("ipc:///tmp/nagmqpull.sock")

poller = zmq.Poller()
poller.register(extsub, flags=zmq.POLLIN)
poller.register(workerpull, flags=zmq.POLLIN)

while True:
	try:
		poller.poll()
	except KeyboardInterrupt:
		break
	
	if(extsub.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		tmsg, pstr = extsub.recv_multipart()
		workerpush.send(pstr)
	if(workerpull.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		pstr = workerpull.recv()
		extpush.send(pstr)

