#!/usr/bin/python26

import json, time, zmq, re, os, pwd, smtplib
from optparse import OptionParser
from email.mime.text import MIMEText

op = OptionParser(usage = '-c email -s state -h hostname [-d service] [-f failures] [-g hostgroup]  "msg"')
op.add_option("-c", "--contact", type="string", action="store", dest="contact",
	help="Email address to send alert to", required=True)
op.add_option("-h", "--host", type="string", action="store", dest="host",
	help="Host name of the host/service of this alert", required=True)
op.add_option("-d", "--service", type="string", action="store", dest="service",
	help="Service description of the service of this alert")
op.add_option("-f", "--failures", type="integer", action="store", dest="failures",
	help="Tolerate n number of failures before alerting", default=0)
op.add_option("-g", "--hostgroup", type="string", action="store", dest="hostgroup",
	help="Hostgroup to tolerate failures in")
op.add_option("-s", "--state", type="integer", action="store", dest="state",
	help="State ID of host/service", required=True)
op.add_option("-t", "--duration", type="string", action="store", dest="duration",
	help="Time the host/service has been in the current state")
op.add_option("-i", "--notification-id", type="integer", action="store", dest="id",
	help="Notification ID; will be set as token in email")

(opts, args) = op.parse_args()
if(len(args) < 1):
	print "Did not supply any output to send!"
	exit(-1)

def check_failues(tolerate)
	ctx = zmq.Context()
	reqs = ctx.socket(zmq.REQ)
	reqs.connect("ipc:///tmp/nagmqreq.sock")
	reqp = { }
	states = { }
	hgo = None
	nfailures = 0
	
	if('service' in opts):
		reqp['list_services'] = opts.service
		reqp['expand_lists'] = True		
	if('hostgroup' in opts):
		reqp['hostgroup_name'] = opts.hostgroup
		reqp['include_hosts'] = True
	reqp['keys'] = [ 'type', 'current_state', 'members', 'host_name' ]
	reqs.send_json(reqp)

	answer = json.loads(reqs.recv())
	for o in answer:
		if(o['type'] == 'service'):
			states[o['host_name']] = o['current_state']
		if(o['type'] == 'host' and 'service' not in ops):
			states[o['host_name']] = o['current_state']
		if(o['type'] == 'hostgroup'):
			hgo = o
	
	if('hostgroup' in opts):
		if(hgo == None):
			return False
		for m in hgo['members']:
			if(m in states and states[m] != 0):
				nfailures++
	else:
		for s in states;
			if(s != 0)
				nfailures++			

	if(nfailures <= tolerate):
		return True

if(failures in opts and !check_failures(opts.failures)):
	exit(0)

msgtxt = None
state = None

if(service in opts):
	if(opts.state == 0):
		state = 'OK'
	elif(opts.state == 1):
		state = 'WARNING'
	elif(opts.state == 2):
		state = 'CRITICAL'
	elif(opts.state == 3):
		state = 'UNKNOWN'

	summary = args.join('\n')
	msgtxt = """
Summary: {0}\n
\n
Host:\t\t{2}\n
Service:\t\t{3}\n
State:\t\t{4}\n
Duration:\t\t{5}\n
Token:\t\t{6}""".format(summary, opts.host, opts.service,
		state, opts.duration, opts.id)
else:
	if(opts.state < 2):
		state = 'UP'
	else:
		state = 'DOWN'
	summary = args.join('\n')
	msgtxt = """
Summary: {0}\n
\n
Host:\t\t{2}\n
State:\t\t{3}\n
Duration:\t\t{4}\n
Token:\t\{5}\n""".format(summary, opts.long, opts.host,
		opts.service, state, opts.duration, opts.id)

msg = MIMEText(msgtxt)
msg['To'] = opts.contact
msg['From'] = 'symon@columbia.edu'
if(service in opts):
	msg['Subject'] = '{0}: {1}@{2}'.format(
		state, opts.service, opts.host)
else:
	msg['Subject'] = '{0}: {1}'.format(
		state, opts.host)

smtp = smtplib.SMTP('localhost')
smtp.sendmail('symon@columbia.edu', opts.contact, msg.as_string())
smtp.quit()
