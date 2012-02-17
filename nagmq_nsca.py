#!/usr/bin/python

import zmq, json, time

context = zmq.Context()
sub = context.socket (zmq.SUB)
sub.connect("tcp://minotaur:5555")
sub.setsockopt(zmq.SUBSCRIBE, 'service_check_processed')
sub.setsockopt(zmq.SUBSCRIBE, 'host_check_processed')
sub.setsockopt(zmq.SUBSCRIBE, 'comment')
sub.setsockopt(zmq.SUBSCRIBE, 'acknowledgement')
sub.setsockopt(zmq.SUBSCRIBE, 'program_status')
push = context.socket(zmq.PUSH)
push.connect("ipc:///tmp/nagmqpush.sock")

lastupdate = 0
failoverat = 120
failedover = False

def send_cmd(name):
	push.send('command', zmq.SNDMORE)
	push.send('{ "type"="command", "command_name"="{0}" }'.format(name))

while True:
	events = sub.poll(120000)
	if(sub.getsockopt(zmq.EVENTS) != zmq.POLLIN and
		time.time() - lastupdate > failoverat and
		failedover == False:
		send_cmd('enable_notifications')
		send_cmd('start_executing_service_checks')
		send_cmd('start_executing_host_checks')
		failedover = True
		continue
	elif failedover == True:
		send_cmd('disable_notifications')
		send_cmd('stop_executing_service_checks')
		send_cmd('stop_executing_host_checks')
		failedover = False

	type, payload = subscriber.recv_multipart()
	status = json.loads(payload)
	lastupdate = status['timestamp']['tv_sec']

	if(type != 'program_status'):
		continue
	if(type == 'service_check_processed'):
		push.send(type, zmq.SNDMORE)
		push.send(payload)

