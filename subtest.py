import zmq
import time
import json
context = zmq.Context()
 
subscriber = context.socket (zmq.SUB)
subscriber.connect("tcp://minotaur:5555")
subscriber.setsockopt(zmq.SUBSCRIBE, 'service_check_initiate')
maxlat = 0

while True:
	message = subscriber.recv()
	print message
