#!/usr/bin/python

import readline, zmq, simplejson as json

zctx = zmq.Context()
reqs = zctx.socket(zmq.REQ)
pubkey = u"7d0:tz+tGVT&*ViD/SzU)dz(3=yIE]aT2TRNrG2$"
privkey = u"FCFo%:3pZTbiQq?MARHYk(<Kp*B-<RpRG7QMUlXr"
serverkey = u"@QxA0C]V9/xwyF?yrLuzJgB4:>lTetaO(EYM%5eD"

reqs.setsockopt_string(zmq.CURVE_PUBLICKEY, pubkey)
reqs.setsockopt_string(zmq.CURVE_SECRETKEY, privkey)
reqs.setsockopt_string(zmq.CURVE_SERVERKEY, serverkey)
reqs.connect('tcp://localhost:5557')

while True:
	s = raw_input('--> ')
	s = reqs.send(json.dumps(json.loads(s)))
	print reqs.recv_json()

