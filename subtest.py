import zmq
import time
context = zmq.Context()
 
subscriber = context.socket (zmq.SUB)
subscriber.connect("tcp://localhost:5555")
subscriber.setsockopt(zmq.SUBSCRIBE, 'service_status')

while True:
	message = subscriber.recv()
	print message
