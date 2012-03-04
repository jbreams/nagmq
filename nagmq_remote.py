#!/usr/bin/python26

import json, time, zmq, re, subprocess, platform, xml.dom.minidom

ctx = zmq.Context()
reqsock = ctx.socket(zmq.REQ)
reqsock.connect("tcp://minotaur.cc.columbia.edu:5557")
pushsock = ctx.socket(zmq.PUSH)
pushsock.connect("tcp://minotaur.cc.columbia.edu:5556")

keys = [ 'type', 'service_description', 'check_interval', 'check_command',
	'accept_passive_service_checks' ]

last_refresh = None
checks = [ ]
last_checked = { }
max_exec_time = 0
sleep_till = None

def refresh_checks():
	if(time.time() - last_refresh < 7200):
		return

	myname = re.sub(r'(?:\.cc)?\.columbia\.edu$', '', platform.node())
	reqsock.send_json({ 'host_name': myname, 'include_services': True,
		'keys': keys })
	resp = json.loads(reqsock.recv())
	checks = [ ]
	for(s in resp):
		if(s['type'] != 'service'):
			continue
		if(s['accept_passive_service_checks'] != True):
			continue

		check_command = re.split(r'(?<!\\)!)', s['check_command'])
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

	doc = Document()
	scd = doc.createElement('SurvivorCheckData')
	scd.setAttribute('Version', '1.0')
	he = doc.createElement('Host')
	he.innerText = s['host_name']
	scd.appendChild(he)
	te = doc.createElement('Timeout')
	te.innerText = '180'
	scd.appendChild(te)
	for o in re.split(r'(?<!\\),', s['check_command'][1]):
		kv = re.split(r'(?<!\\)=', o, maxsplit=2)
		moe = doc.createElement('ModuleOption')
		moe.setAttribute('OptionName', kv[0])
		ove = doc.createElement('OptionValue')
		ove.innerText = kv[1]
		moe.appendChild(ove)
		scd.appendChild(moe)
	return doc.toxml()

def run_check(svc):
	stime = time.time()
	proc = subprocess.popen("/usr/survivor/mods/{0}".format(
		svc['check_command'][0]), bufsize=1, stdin=PIPE, stdout=PIPE)
	(sout, serr) = proc.communicate(input=stupid_xml_for_check(svc))
	etime = time.time()
	if(etime - stime > max_exec_time):
		max_exec_time = etime
	status = {
		'type': 'service_check_processed'
		'host_name': svc['host_name'],
		'service_description': svc['service_description'],
		'output': sout,
		'return_code': proc.returncode
		'end_time': { 'tv_sec': etime }
	}
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
		if(nextrun < lowest_nextrun or lowest_nextrun = None):
			lowest_nextrun = nextrun
	if(lowest_nextrun - time.time() < 0):
		continue
	sleep(lowest_nextrun - time.time())
