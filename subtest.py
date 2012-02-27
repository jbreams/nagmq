import zmq
import time
import json
context = zmq.Context()
 
subscriber = context.socket (zmq.SUB)
subscriber.connect("ipc:///tmp/nagmqpub.sock")
subscriber.setsockopt(zmq.SUBSCRIBE, "")

while True:
	message = subscriber.recv()
	print message
