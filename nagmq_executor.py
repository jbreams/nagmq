#!/usr/bin/python26

import json, time, zmq, re, subprocess, threading, shlex

zc = zmq.Context()
intpull = zc.socket(zmq.PULL)
intpull.bind("inproc://internalresults")
extsub = zc.socket(zmq.SUB)
extsub.connect("ipc:///tmp/nagmqpub.sock")
extsub.setsockopt(zmq.SUBSCRIBE, 'host_check_initiate')
extsub.setsockopt(zmq.SUBSCRIBE, 'service_check_initiate')
extpush = zc.socket(zmq.PUSH)
extpush.connect("ipc:///tmp/nagmqpull.sock")

keystocopy = [ 'host_name', 'service_description', 'check_options',
	'scheduled_check', 'reschedule_check', 'latency', 'early_timeout',
	'check_type' ]

class ExecThread(threading.Thread):
	def __init__(self, cmd):
		self.cmd = cmd
		threading.Thread.__init__(self)

	def run(self):
		intpush = zc.socket(zmq.PUSH)
		intpush.connect("inproc://internalresults")
		tosend = { }
		for i in keystocopy:
			if(i in cmd):
				tosend[i] = cmd[i]
		start = time.time()
		finish = None
		try:
			args = shlex.split(str(cmd['command_line']))
			proc = subprocess.Popen(args,
			stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			(sout, serr) = proc.communicate()
			proc.wait()
		except Exception, e:
			finish = time.time()
			tosend['exited_ok'] = 0
			tosend['return_code'] = -1
			tosend['output'] = e
		finish = time.time()

		if('output' not in tosend):
			tosend['exited_ok'] = 1
			tosend['return_code'] = proc.returncode
			tosend['output'] = sout
		tosend['start_time'] = { 'tv_sec': int(start) }
		tosend['finish_time'] = { 'tv_sec': int(finish) }
			
		if('service_description' in cmd):
			tosend['type'] = 'service_check_processed'
			tosend['service_description'] = cmd['service_description']
		else:
			tosend['type'] = 'host_check_processed'
		print tosend
		intpush.send_json(tosend)


poller = zmq.Poller()
poller.register(extsub, flags=zmq.POLLIN)
poller.register(intpull, flags=zmq.POLLIN)

print "Starting poller"

while True:
	try:
		poller.poll()
	except KeyboardInterrupt:
		break
	except Exception, e:
		print e

	if(extsub.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		tmsg, pstr = extsub.recv_multipart()
		cmd = json.loads(pstr)
		t = ExecThread(cmd)
		t.start()
	elif(intpull.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		pstr = intpull.recv()
		extpush.send(pstr)

print "End of loop!"
