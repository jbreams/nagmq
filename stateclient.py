#!/usr/bin/python

import readline, zmq, simplejson as json

zctx = zmq.Context()
reqs = zctx.socket(zmq.REQ)
reqs.connect('ipc:///var/nagios/nagmqstate.sock')

while True:
	s = raw_input('--> ')
	s = reqs.send(s)
	print reqs.recv_json()

