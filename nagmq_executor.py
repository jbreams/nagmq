#!/usr/bin/python26

import json, time, zmq, re, subprocess, threading, shlex, os, pwd

zc = zmq.Context()
intquit = zc.socket(zmq.PUB)
intquit.bind("inproc://internalquit")
intpub = zc.socket(zmq.PUSH)
intpub.bind("inproc://internalwork")
extsub = zc.socket(zmq.SUB)
extsub.connect("ipc:///tmp/nagmqpub.sock")
extsub.setsockopt(zmq.SUBSCRIBE, 'host_check_initiate')
extsub.setsockopt(zmq.SUBSCRIBE, 'service_check_initiate')
extpull = zc.socket(zmq.PULL)
extpull.bind("ipc:///tmp/nagmq_workqueue.sock")
nthreads = 20
checkspooldir = '/var/nagios/spool/checkresults'
naguid, naggid = getpwnam('nagios')[2:3]


svc_fmt = """
### Active Check Result File ###\n
file_time={0}\n\n
### Nagios Service Check Result ###\n
# Time: {1}
host_name={2}\n
service_description={3}\n
check_type={4}\n
check_options={5}\n
scheduled_check={6}\n
reschedule_check={7}\n
latency={8}\n
start_time={9}\n
finish_time={10}\n
early_timeout={11}\n
exited_ok={12}\n
return_code={13}\n
output={14}\n"""

host_fmt = """
### Active Check Result File ###\n
file_time={0}\n\n
### Nagios Host Check Result ###\n
# Time: {1}
host_name={2}\n
check_type={3}\n
check_options={4}\n
scheduled_check={5}\n
reschedule_check={6}\n
latency={7}\n
start_time={8}\n
finish_time={9}\n
early_timeout={10}\n
exited_ok={11}\n
return_code={12}\n
output={13}\n"""


class ExecThread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)

	def run(self):
		intsub = zc.socket(zmq.PULL)
		intsub.connect("inproc://internalwork")
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
			output = None
			start = time.time()
			try:
				args = shlex.split(str(cmd['command_line']))
				proc = subprocess.Popen(args,
				stdin=subprocess.PIPE, stdout=subprocess.PIPE)
				(sout, serr) = proc.communicate()
				proc.wait()
				finish = time.time()
			except Exception, e:
			 	finish = time.time()
			 	if('service_description' in cmd):
					output = svc_fmt.format(int(start), time.ctime(start),
						cmd['host_name'], cmd['service_description'],
						cmd['check_type'], cmd['check_options'],
						cmd['scheduled_check'], cmd['reschedule_check'],
						cmd['latency'], start, finish, 0, 0,
						1, e)
				else:
					output = host_fmt.format(int(start), time.ctime(start),
						cmd['host_name'], cmd['check_type'], cmd['check_options'],
						cmd['scheduled_check'], cmd['reschedule_check'],
						cmd['latency'], start, finish, 0, 0,
						1, e)
				continue


			if(output == None):
				if('service_description' in cmd):
					output = svc_fmt.format(int(start), time.ctime(start),
						cmd['host_name'], cmd['service_description'],
						cmd['check_type'], cmd['check_options'],
						cmd['scheduled_check'], cmd['reschedule_check'],
						cmd['latency'], start, finish, 0, 1,
						proc.returncode, sout)
				else:
					output = host_fmt.format(int(start), time.ctime(start),
						cmd['host_name'], cmd['check_type'], cmd['check_options'],
						cmd['scheduled_check'], cmd['reschedule_check'],
						cmd['latency'], start, finish, 0, 1,
						proc.returncode, sout)
			
			filename = os.tempnam(checkspooldir, 'check')
			with open(filename, 'w') as f:
				f.write(output)
				okf = open(filename + '.ok', 'w')
				os.chown(f, naguid, naggid)
				os.chmod(f, 640)
				os.chown(okf, naguid, naggid)
				os.chmod(f, 640)
				okf.close()
			f.close()


for i in range(nthreads):
	t = ExecThread()
	t.start()

poller = zmq.Poller()
poller.register(extsub, flags=zmq.POLLIN)
poller.register(extpull, flags=zmq.POLLIN)

print "Starting poller"

while True:
	try:
		poller.poll()
	except KeyboardInterrupt:
		break
	except Exception, e:
		print e

	pstr = None
	if(extsub.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		tmsg, pstr = extsub.recv_multipart()
	elif(extpull.getsockopt(zmq.EVENTS) == zmq.POLLIN):
		pstr = intpull.recv()
	if(pstr != None):
		intpub.send(pstr)

print "End of loop!"
intquit.send('stop_running')
