#!/usr/bin/python

use zmq, json

subscriber = context.socket (zmq.SUB)
subscriber.connect("tcp://localhost:5555")
subscriber.setsockopt(zmq.SUBSCRIBE, 'service_status')
subscriber.setsockopt(zmq.SUBSCRIBE, 'host_status')

pipe = open('/var/nagios/rw/nagios.cmd', 'w')

while True:
	type = subscriber.recv()
	msg = subscriber.recv()

	status = json.loads(msg)
	if(type == 'service_status'):
		pipe.write("[{0}] PROCESS_SERVICE_CHECK_RESULT;{1};{2};{3};{4}\n".format(
			status['timestamp'], status['host_name'], status['service_description'],
			status['return_code'], status['plugin_output']))
	else:
		pipe.write("[{0}] PROCESS_HOST_CHECK_RESULT;{1};{2};{3}\n".format(
			status['timestamp'], status['host_name'], status['return_code'],
			status['plugin_output']))
	pipe.flush()

