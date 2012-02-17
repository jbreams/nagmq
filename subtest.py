import zmq
import time
import json
context = zmq.Context()
 
subscriber = context.socket (zmq.SUB)
subscriber.connect("ipc:///tmp/nagmq.sock")
subscriber.setsockopt(zmq.SUBSCRIBE, "statechange")

while True:
	message = subscriber.recv()
	print message
