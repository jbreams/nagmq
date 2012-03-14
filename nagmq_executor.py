#!/usr/bin/python26

import json, time, zmq, re, subprocess, threading, shlex

zc = zmq.Context()
intquit = zc.socket(zmq.PUB)
intquit.bind("inproc://internalquit")
intpub = zc.socket(zmq.PUSH)
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
		intsub = zc.socket(zmq.PULL)
		intsub.connect("inproc://internalwork")
		intpush = zc.socket(zmq.PUSH)
		intpush.connect("inproc://internalresults")
		localquit = zc.socket(zmq.SUB)
		localquit.connect("inproc://internalquit")
		localquit.setsockopt(zmq.SUBSCRIBE, 'stop_running')

		poller = zmq.Poller()
		poller.register(intsub, flags=zmq.POLLIN)
		poller.register(localquit, flags=zmq.POLLIN)
		while True:
			try:
				poller.poll()
				if(localquit.getsockopt(zmq.EVENTS) == zmq.POLLIN):
					break
				else:
					pstr = intsub.recv()
			except Exception, e:
				print e
				continue
			cmd = json.loads(pstr)
			try:
				args = shlex.split(str(cmd['command_line']))
				proc = subprocess.Popen(args,
				stdin=subprocess.PIPE, stdout=subprocess.PIPE)
				(sout, serr) = proc.communicate()
				proc.wait()
			except Exception, e:
				print e
				continue
			output = sout.splitlines()[0].split('|')[0]

			tosend = { 'host_name': cmd['host_name'], 'output': output,
				'return_code': proc.returncode, 'end_time': { 'tv_sec' : int(time.time()) } }	
		
			if('service_description' in cmd):
				tosend['type'] = 'service_check_processed'
				tosend['service_description'] = cmd['service_description']
			else:
				tosend['type'] = 'host_check_processed'
			print tosend
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
		intpub.send(pstr)
	elif(intpull.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		pstr = intpull.recv()
		extpush.send(pstr)

print "End of loop!"
intquit.send('stop_running')
