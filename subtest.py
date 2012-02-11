import zmq
import time
import json
context = zmq.Context()
 
subscriber = context.socket (zmq.SUB)
subscriber.connect("tcp://localhost:5555")
subscriber.setsockopt(zmq.SUBSCRIBE, 'service_check')
maxlat = 0

while True:
	message = subscriber.recv()
	print message
