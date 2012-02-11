#!/usr/bin/python

import zmq, json

context = zmq.Context()
subscriber = context.socket (zmq.SUB)
subscriber.connect("tcp://localhost:5555")
subscriber.setsockopt(zmq.SUBSCRIBE, 'service_check_processed')
subscriber.setsockopt(zmq.SUBSCRIBE, 'host_check_processed')
subscriber.setsockopt(zmq.SUBSCRIBE, 'comment')
subscriber.setsockopt(zmq.SUBSCRIBE, 'acknowledgement')
subscriber.setsockopt(zmq.SUBSCRIBE, 'program_status')

pipe = open('nagios.cmd', 'w')
lastupdate = 0
failoverat = 120000
failedover = False

while True:
	events = subscriber.poll(120000)
	if events == 0 and time.time() * 1000 - lastupdate > failoverat:
		pipe.write("[{0}] ENABLE_NOTIFICATIONS\n".format(time.time()))
		pipe.write("[{0}] START_EXECUTING_SVC_CHECKS\n".format(time.time()))
		pipe.write("[{0}] START_EXECUTING_HOST_CHECKS\n".format(time.time()))
		failedover = True
		continue
	elif failedover == True:
		pipe.write("[{0}] DISABLE_NOTIFICATIONS\n".format(time.time()))
		pipe.write("[{0}] STOP_EXECUTING_SVC_CHECKS\n".format(time.time()))
		pipe.write("[{0}] STOP_EXECUTING_HOST_CHECKS\n".format(time.time()))

	type, payload = subscriber.recv_multipart()
	status = json.loads(payload)
	timestamp = status['timestamp']['tv_sec']
	if(type == 'service_status'):
		print status
		pipe.write("[{0}] PROCESS_SERVICE_CHECK_RESULT;{1};{2};{3};{4}\n".format(
			timestamp, status['host_name'], status['service_description'],
			status['return_code'], status['plugin_output']))
	elif(type == 'host_status'):
		pipe.write("[{0}] PROCESS_HOST_CHECK_RESULT;{1};{2};{3}\n".format(
			timestamp, status['host_name'], status['return_code'],
			status['plugin_output']))
	elif(type == 'comment'):
		if(status['operation'] != 'add'):
			continue
		if 'service_description' in status:
			pipe.write("[{0}] ADD_SVC_COMMENT;{1};{2};{3};{4};{5}\n",
				timestamp, status['host_name'],
				status['service_description'],status['persistent'],
				status['author'],status['comment_data'])
		else:
			pipe.write("[{0}] ADD_HOST_COMMENT;{1};{2};{3};{4}\n",
				timestamp, status['host_name'], status['persistent'],
				status['author'],status['comment_data'])
	elif(type == 'acknowledgement'):
		if(status['operation'] != 'add'):
			continue
		if 'service_description' in status:
			pipe.write("[{0}] ACKNOWLEDGE_SERVICE_PROBLEM;{1};{2};{3};{4};{5};{6};{7}\n",
				timestamp, status['host_name'],
				status['service_description'], status['is_sticky'],
				status['notify_contacts'], status['persistent_comment'],
				status['author_name'],status['comment_data'])
		else:
			pipe.write("[{0}] ACKNOWLEDGE_HOST_PROBLEM;{1};{2};{3};{4};{5};{6}\n",
				timestamp, status['host_name'], status['is_sticky'],
				status['notify_contacts'], status['persistent_comment'],
				status['author_name'],status['comment_data'])
	pipe.flush()

