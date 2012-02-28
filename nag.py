#!/usr/bin/python26

import json, time, zmq, re
from optparse import OptionParser

op = OptionParser(usage = "[opts] {verb} {noun} [service]@{host|hostgroup}")
op.add_option("-c", "--comment", type="string", action="store", dest="comment",
	help="The comment to be added to the command")
op.add_option("-p", "--persistent", action="store_true", dest="persistent",
	help="Any comment created will be persistent")
op.add_option("-n", "--notify", action="store_true", dest="notify",
	help="Notify contacts about action")

(opts, args) = op.parse_args()
if(len(args) < 2):
	print "Did not specify enough arguments!"
	exit(-1)

validverbs = [ 'start', 'stop', 'add', 'remove', 'check' ]
validnouns = [ 'acknowledgement', 'notifications', 'checks' ]
myverb = None
mynoun = None
mysvc = None
mytarget = None

for i in validverbs:
	if(i == args[0]):
		myverb = i
		break
if(myverb != 'check' and len(args) < 3):
	print "Did not specify enough arguments for {0}".format(myverb)
	exit(-1)
else:
	for i in validnouns:
		if(i == args[1]):
			mynoun = i
			break

if(myverb == None or (myverb != 'check' and mynoun == None)):
	print "Did not specify a valid noun or verb!"
	exit(-1)

argn = 2;
if(myverb == 'check'):
	argn = 1
tm = re.match(r'([^\@]+)?\@?([^\s]+)?', args[argn])
mysvc = tm.group(1)
mytarget = tm.group(2)

print "{0} @ {1}".format(mysvc, mytarget)

services = [ ]
hosts = [ ]
contacts = [ ]

ctx = zmq.Context()
reqsock = ctx.socket(zmq.REQ)
reqsock.connect("tcp://minotaur.cc.columbia.edu:5555")

def parse_object(o, lr):
	if(o['type'] == 'hostgroup'):
		for h in o['members']:
			hosts.append(h)
	elif(o['type'] == 'host'):
		hosts.append(o['host_name'])
		for h in o['services']:
			if((mytarget != None or lr == True) and mysvc != h):
				continue
			services.append(dict(host_name=o['host_name'],
				service_description=h))
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
		services.append(dict(host_name=o['host_name'],
			service_description=o['service_description']))
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
	print raw
	resp = json.loads(raw)
	for o in resp:
		parse_object(o, False)

	targetreq = dict(hostgroup_name=mysvc, include_hosts=True, brief=True)
	reqsock.send_json(targetreq)
	resp = json.loads(reqsock.recv())
	for o in resp:
		parse_object(o, False)
	
hosts = list(set(hosts))
contacts = list(set(contacts))

if(len(services) == 0 and len(hosts) == 0):
	if(mytarget):
		print "Could not find any matching services or hosts";
		exit(-1);
	else:
		reqsock.send_json(dict(list_services=mysvc, expand_lists=True, brief=True, include_hosts=True))
		resp = json.loads(reqsock.recv())
		for o in resp:
			parse_object(o, True)

hosts = list(set(hosts))
contacts = list(set(contacts))

print hosts
print services
print contacts
