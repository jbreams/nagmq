#!/usr/bin/python

import zmq

ctx = zmq.Context();
req = ctx.socket(zmq.XREQ)
rep = ctx.socket(zmq.XREP)

rep.bind("tcp://*:5555")
req.connect("ipc:///tmp/nagmqreq.sock")
#sub.setsockopt(zmq.SUBSCRIBE, '')
zmq.device(zmq.QUEUE, rep, req)
