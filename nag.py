#!/usr/bin/python26

import json, time, zmq, re, os, pwd
from optparse import OptionParser

op = OptionParser(usage = "[opts] {verb} {noun} [service]@{host|hostgroup}")
op.add_option("-c", "--comment", type="string", action="store", dest="comment",
	help="The comment to be added to the command", default="")
op.add_option("-p", "--persistent", action="store_true", dest="persistent",
	help="Any comment created will be persistent", default=False)
op.add_option("-n", "--notify", action="store_true", dest="notify",
	help="Notify contacts about action", default=False)

(opts, args) = op.parse_args()
if(len(args) < 2):
	print "Did not specify enough arguments!"
	exit(-1)
print opts

validverbs = [ 'start', 'stop', 'add', 'remove', 'check', 'status' ]
validnouns = [ 'acknowledgement', 'notifications', 'checks' ]
myverb = None
mynoun = None
mysvc = None
mytarget = None

for i in validverbs:
	if(i == args[0]):
		myverb = i
		break
if((myverb != 'check' and myverb != 'status') and len(args) < 3):
	print "Did not specify enough arguments for {0}".format(myverb)
	exit(-1)
else:
	for i in validnouns:
		if(i == args[1]):
			mynoun = i
			break

if(myverb == None or
	((myverb != 'check' and myverb != 'status') and mynoun == None)):
	print "Did not specify a valid noun or verb!"
	exit(-1)

argn = 2;
if(myverb == 'check' or myverb == 'status'):
	argn = 1
tm = re.match(r'([^\@]+)?\@?([^\s]+)?', args[argn])
mysvc = tm.group(1)
mytarget = tm.group(2)

services = dict()
hosts = dict()
contacts = [ ]

ctx = zmq.Context()
reqsock = ctx.socket(zmq.REQ)
reqsock.connect("tcp://minotaur.cc.columbia.edu:5557")

def parse_object(o, lr):
	if(o['type'] == 'hostgroup'):
		for h in o['members']:
			if h not in hosts:
				reqsock.send_json({'host_name': h, 'include_contacts': True})
				resp = json.loads(reqsock.recv());
				for so in resp:
					parse_object(so, lr)
	elif(o['type'] == 'host'):
		hosts[o['host_name']] = o
		for s in o['services']:
			if((mytarget != None or lr == True) and mysvc != s):
				continue
			name = "{0}@{1}".format(s, o['host_name'])
			if(name not in services):
				reqsock.send_json({'host_name': o['host_name'],
					'service_description': s, 'include_contacts': True})
				resp = json.loads(reqsock.recv());
				for so in resp:
					parse_object(so, lr)
		if(o['contacts'] != None):
			for c in o['contacts']:
				contacts.append(c)
		if(o['contact_groups'] != None):
			for g in o['contact_groups']:
				reqsock.send_json(dict(contactgroup_name=g))
				resp = json.loads(reqsock.recv())
				for co in resp:
					parse_object(co, lr)
	elif(o['type'] == 'service'):
		name = "{0}@{1}".format(o['service_description'], o['host_name'])
		services[name] = o
		if(o['contacts'] != None):
			for c in o['contacts']:
				contacts.append(c)
		if(o['contact_groups'] != None):
			for g in o['contact_groups']:
				reqsock.send_json(dict(contactgroup_name=g))
				resp = json.loads(reqsock.recv())
				for co in resp:
					parse_object(co, lr)		
	elif(o['type'] == 'contact'):
		contacts.append(o['name'])
	elif(o['type'] == 'contactgroup'):
		for c in o['members']:
			contacts.append(c)

			
if(mytarget != None):
	targetreq = dict(host_name=mytarget, include_contacts=True, brief=True)
	reqsock.send_json(targetreq)
	resp = json.loads(reqsock.recv())
	for o in resp:
		parse_object(o, False)

	targetreq = dict(hostgroup_name=mytarget, brief=True,
		include_hosts=True, include_contacts=True)
	reqsock.send_json(targetreq)
	resp = json.loads(reqsock.recv())
	for o in resp:
		parse_object(o, False)

else:
	targetreq = dict(host_name=mysvc)
	reqsock.send_json(targetreq)
	raw = reqsock.recv()
	resp = json.loads(raw)
	for o in resp:
		parse_object(o, False)

	targetreq = dict(hostgroup_name=mysvc, include_hosts=True, brief=True)
	reqsock.send_json(targetreq)
	resp = json.loads(reqsock.recv())
	for o in resp:
		parse_object(o, False)
	
justservices = False
if(len(services) == 0 and len(hosts) == 0):
	if(mytarget):
		print "Could not find any matching services or hosts";
		exit(-1);
	else:
		reqsock.send_json(dict(list_services=mysvc, expand_lists=True,
			brief=True, include_hosts=True))
		resp = json.loads(reqsock.recv())
		for o in resp:
			parse_object(o, True)
	justservices = True

contacts = list(set(contacts))

def status_to_string(val, ishost):
	if(ishost):
		if(val < 2):
			return "OK"
		else:
			return "CRITICAL"
	else:
		if(val == 0):
			return "OK"
		elif(val == 1):
			return "WARNING"
		elif(val == 2):
			return "CRITICAL"
		elif(val == 3):
			return "UNKNOWN"

username = pwd.getpwuid(os.getuid())[0]
if(username not in contacts):
	print "{0} not authorized to view target".format(username)
#	exit(-1)

if(myverb == 'status'):
	for h in sorted(hosts.keys()):
		if(mytarget == None and justservices != True):
			print "[{0}]: {1} {2}".format(
				h, status_to_string(hosts[h]['current_state'], False),
					hosts[h]['plugin_output'])
		for s in sorted(hosts[h]['services']):
			name = "{0}@{1}".format(s, h)
			if(name in services):
				print "[{0}]: {1} {2}".format(
					name, status_to_string(services[name]['current_state'], False),
					services[name]['plugin_output'])
elif(myverb == 'check'):
	print "Not implemented!"
else:
	pushsock = ctx.socket(zmq.PUSH)
	pushsock.connect("ipc:///tmp/nagmqpull.sock")
	for h in sorted(hosts.keys()):
		if(myverb == 'add' and mynoun == 'acknowledgement'):
			cmd = { 'type':'acknowledgement', 'host_name':h,
				'author_name':username, 'comment_data': opts.comment,
				'time_stamp': { 'tv_sec': time.time() }, 'notify_contacts':opts.notify,
				'persistent_comment':opts.persistent }
			if(mytarget == None and justservices != True):
				if(hosts[h]['current_state'] == 0):
					print "[{0}]: No hard problem".format(h)
				elif(hosts[h]['problem_has_been_acknowledged'] == False):
					print "[{0}]: Acknowledged".format(h)
					pushsock.send_json(cmd)
				else:
					print "[{0}]: Already acknowledged".format(h)
			for s in sorted(hosts[h]['services']):
				name = "{0}@{1}".format(s, h)
				if(name in services):
					if(services[name]['current_state'] == 0):
						print "[{0}]: No hard problem".format(name)
					elif(services[name]['problem_has_been_acknowledged'] == False):
						cmd['service_description'] = s
						pushsock.send_json(cmd)
						print "[{0}]: Acknowledged".format(name)
					else:
						print "[{0}]: Already acknowledged".format(name)
		elif(myverb == 'remove' and mynoun == 'acknowledgement'):
			cmd = { 'host_name':h, 'type':'command',
				command:'remove_host_acknowledgement' }
                        if(mytarget == None and justservices != True):
				if(hosts[h]['problem_has_been_acknowledged'] == True):
					print "[{0}]: Acknowledgment removed".format(h)
					pushsock.send_json(cmd)
				else:
					print "[{0}]: No acknowledgement to remove".format(h)
			for s in sorted(hosts[h]['services']):
				name = "{0}@{1}".format(s, h)
				if(name in services):
					if(services[name]['problem_has_been_acknowledged'] == True):
						cmd['service_description'] = s
						cmd['command'] = 'remove_service_acknowledgement'
						pushsock.send_json(cmd)
						print "[{0}]: Acknowledgment removed".format(name)
					else:
						print "[{0}]: No acknowledgement to remove".format(name)
		elif(myverb == 'start' or myverb == 'stop'):
			cmd = { 'host_name':h, 'type':'command' }
			if(mynoun == 'notifications' and (mytarget == None and justservices != True)):
				if(myverb == 'start'):
					cmd['command'] = 'start_host_notifications'
					print "[{0}]: Notifications enabled".format(h)
				else:
					cmd['command'] = 'stop_host_notifications'
					print "[{0}]: Notifications already enabled".format(h)
				pushsock.send_json(cmd)
			if(mynoun == 'checks' and (mytarget == None and justservices != True)):
				if(myverb == 'start'):
					print "[{0}]: Checks enabled".format(h)
					cmd['command'] = 'enable_host_checks'
				else:
					print "[{0}]: Checks already enabled".format(h)
					cmd['command'] = 'disable_host_checks'
				pushsock.send_json(cmd)

			for s in sorted(hosts[h]['services']):
				name = "{0}@{1}".format(s, h)
				if(name in services):
					cmd['service_description'] = s
					if(mynoun == 'notifications'):
						if(myverb == 'start'):
							print "[{0}]: Notifications enabled".format(name)
							cmd['command'] = 'start_service_notifications'
						else:
							print "[{0}]: Notifications disabled".format(name)
							cmd['command'] = 'stop_service_notifications'
						pushsock.send_json(cmd)
					if(mynoun == 'checks'):
						if(myverb == 'start'):
							print "[{0}]: Checks enabled".format(name)
							cmd['command'] = 'enable_service_checks'
						else:
							print "[{0}]: Checks disabled".format(name)
							cmd['command'] = 'stop_service_checks'
						print cmd
						pushsock.send_json(cmd)

