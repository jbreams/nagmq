#!/usr/bin/python26

import json, time, zmq, re, subprocess, threading, signal

zc = zmq.Context()
intpub = zc.socket(zmq.PUB)
intpub.bind("inproc://internalwork")
intpull = zc.socket(zmq.PULL)
intpull.bind("inproc://internalresults")
extsub = zc.socket(zmq.SUB)
extsub.connect("ipc:///tmp/nagmqpub.sock")
extsub.setsockopt(zmq.SUBSCRIBE, 'host_check_initiate')
extsub.setsockopt(zmq.SUBSCRIBE, 'service_check_initiate')
extpush = zc.socket(zmq.PUSH)
extpush.connect("ipc:///tmp/nagmqpull.sock")
nthreads = 20

class ExecThread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		intsub = zc.socket(zmq.SUB)
		intsub.connect("inproc://internalwork")
		intsub.setsockopt(zmq.SUBSCRIBE, '')
		intpush = zc.socket(zmq.PUSH)
		intpush.connect("inproc://internalresults")
		keeprunning = True

		while True:
			try:
				tmsg, pstr = intsub.recv_multipart()
			except Exception, e:
				print e
				break
			if(tmsg == 'stop_running'):
				break
			cmd = json.loads(pstr)
			proc = subprocess.Popen(cmd['command_line'],
				stdin=subprocess.PIPE, stdout=subprocess.PIPE,
				sterr=subprocess.PIPE)
			(sout, serr) = proc.communicate()
			proc.wait()
			output = sout.splitlines[0].partition('|')

			tosend = { 'host_name': cmd['host_name'], 'output': output,
				'return_code': returncode, 'end_time': { 'tv_sec' : end } }	
		
			if('service_description' in cmd):
				tosend['type'] = 'service_check_processed'
				tosend['service_description'] = cmd['service_description']
			else:
				tosend['type'] = 'host_check_processed'
			intpush.send_json(tosend)

for i in range(nthreads):
	t = ExecThread()
	t.start()

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
		intpub.send_multipart([tmsg, pstr])
	elif(intpull.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		pstr = intpull.recv()
		extpush.send(pstr)

print "End of loop!"
intpub.send_multipart(['stop_running', '{ }'])
