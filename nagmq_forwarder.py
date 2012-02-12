#!/usr/bin/python

import zmq

ctx = zmq.Context();
pub = ctx.socket(zmq.PUB)
sub = ctx.socket(zmq.SUB)

pub.bind("tcp://*:5555")
sub.connect("ipc:///tmp/nagmq.sock")
sub.setsockopt(zmq.SUBSCRIBE, '')
zmq.device(zmq.FORWARDER, sub, pub)
