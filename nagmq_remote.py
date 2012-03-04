#!/usr/bin/python26

import json, time, zmq, re, subprocess, platform, xml.dom.minidom
ctx = zmq.Context()
reqsock = ctx.socket(zmq.REQ)
reqsock.connect("ipc:///tmp/nagmqreq.sock")
#reqsock.connect("tcp://minotaur.cc.columbia.edu:5557")
pushsock = ctx.socket(zmq.PUSH)
pushsock.connect("ipc:///tmp/nagmqpull.sock")
#pushsock.connect("tcp://minotaur.cc.columbia.edu:5556")

keys = [ 'type', 'service_description', 'check_interval', 'check_command',
	'accept_passive_service_checks' ]

last_refresh = 0
checks = [ ]
last_run = { }
max_exec_time = 0
sleep_till = None
myname = re.sub(r'(?:\.cc)?\.columbia\.edu$', '', platform.node())

def refresh_checks():
	global last_refresh, checks
	interval = time.time() - last_refresh
	print interval
	if(interval  < 7200):
		return
	reqsock.send_json({ 'host_name': myname, 'include_services': True,
		'keys': keys })
	resp = json.loads(reqsock.recv())
	checks = [ ]
	for s in resp:
		if(s['type'] != 'service'):
			continue
		if(s['accept_passive_service_checks'] != True):
			continue

		check_command = re.split(r'(?<!\\)!', s['check_command'])
		if(check_command[0] != 'check_by_sr'):
			continue
		check_command.pop(0)
		s['check_command'] = check_command
		checks.append(s)
	last_refresh = time.time()

def stupid_xml_for_check(s):
	# The programmer is a jerk face and decided to use crazy horrible
	# XML as the transport for sending check data around. This programmer's
	# only consolation is that the programmer looks like a squirrel.

	doc = xml.dom.minidom.Document()
	scd = doc.createElement('SurvivorCheckData')
	doc.appendChild(scd)
	scd.setAttribute('Version', '1.0')
	he = doc.createElement('Host')
	he.appendChild(doc.createTextNode('localhost'))
	scd.appendChild(he)
	te = doc.createElement('Timeout')
	te.appendChild(doc.createTextNode('120'))
	scd.appendChild(te)
	if(s['check_command'][1] == ''):
		return re.sub('\?>', '?>\n', doc.toxml(encoding='iso-8859-1'))
	for o in re.split(r'(?<!\\),', s['check_command'][1]):
		kv = re.split(r'(?<!\\)=', o, maxsplit=2)
		moe = doc.createElement('ModuleOption')
		moe.setAttribute('OptionName', kv[0])
		ove = doc.createElement('OptionValue')
		val =  kv[1]
		ove.appendChild(doc.createTextNode(val))
		moe.appendChild(ove)
		scd.appendChild(moe)
	return re.sub('\?>', '?>\n', doc.toxml(encoding='iso-8859-1'))

def run_check(svc):
	global max_exec_time
	stime = time.time()
	status = {
		'type': 'service_check_processed',
		'host_name': myname,
		'service_description': svc['service_description']
	}
	cmdline = "/usr/survivor/mod/check/{0}".format(svc['check_command'][0])
	try:
		proc = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(sout, serr) = proc.communicate(input=stupid_xml_for_check(svc))
		outdom = xml.dom.minidom.parseString(sout)
		outelem = outdom.getElementsByTagName('Comment')[0]
		retcode = outdom.getElementsByTagName('ReturnCode')[0]
		status['output'] = outelem.firstChild.nodeValue
		status['return_code'] = int(retcode.firstChild.nodeValue)
		proc.wait()
	except Exception as e: 
		status['output'] = e
		status['return_code'] = 4
		print svc
	etime = time.time()
	if(etime - stime > max_exec_time):
		max_exec_time = etime
	status['end_time'] = { 'tv_sec': int(etime) }
	pushsock.send_json(status)
	last_run[svc['service_description']] = etime

while 1:
	lowest_nextrun = None
	refresh_checks()
	for s in checks:
		interval = s['check_interval'] * 60
		if(s['service_description'] not in last_run):
			run_check(s)
			nextrun = time.time() + interval
		elif(last_run[s['service_description']] + interval >= time.time()):
			run_check(s)
			nextrun = time.time() + interval
		else:
			nextrun = last_run[s['service_description']] + interval
		if(nextrun < lowest_nextrun or lowest_nextrun == None):
			lowest_nextrun = nextrun
		print nextrun
	if(lowest_nextrun - time.time() < 0):
		continue
	time.sleep(lowest_nextrun - time.time())
