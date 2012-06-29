#!/usr/bin/python26

import json, time, zmq, re, os, pwd, types
from optparse import OptionParser
from collections import deque
from datetime import timedelta, datetime

op = OptionParser(usage = "[opts] {verb} {noun} [service]@{host|hostgroup}")
op.add_option("-c", "--comment", type="string", action="store", dest="comment",
	help="The comment to be added to the command", default="")
op.add_option("-p", "--persistent", action="store_true", dest="persistent",
	help="Any comment created will be persistent", default=False)
op.add_option("-n", "--notify", action="store_true", dest="notify",
	help="Notify contacts about action", default=False)
op.add_option("--config-file", action="store", type="string", dest="configfile",
	help="Overrides default nagmq config file", default="/etc/nagios/nagmq.conf")
op.add_option("-s", "--start", type="string", action="store", dest="starttime",
	help="Start time for downtime")
op.add_option("-e", "--end", type="string", action="store", dest="endtime",
	help="End time for downtime")
op.add_option("-f", "--flexible", action="store_true", dest="flexible",
	help="Specifies downtime should be flexible", default=False)
op.add_option('-d', '--duration', type="string", dest="duration",
	help="Specify duration instead of times for downtime")
op.add_option('-x', '--hosts-only', action='store_true', dest='hostsonly',
	help='Only look for hosts when parsing arguments', default=False)


(opts, args) = op.parse_args()
args = deque(args)

verbmap = { 
	'enable': [ 'checks', 'notifications', 'eventhandler' ],
	'disable': [ 'checks', 'notifications', 'eventhandler' ],
	'add': ['acknowledgement', 'comment', 'downtime' ],
	'remove': ['acknowledgement', 'downtime' ],
	'status': [ ],
}

pasttenses = {
	'enable': 'enabled',
	'disable': 'disabled',
	'add': 'added',
	'remove': 'removed'
}

keys = ['host_name', 'services', 'hosts', 'contacts', 'contact_groups',
	'service_description', 'current_state', 'members', 'type', 'name',
	'problem_has_been_acknowledged', 'plugin_output', 'checks_enabled',
	'notifications_enabled', 'event_handler_enabled' ]
myverb = None
mynoun = None

if(len(args) < 2):
	print "Did not specify enough arguments!"
	exit(1)
for v in verbmap:
	if v.startswith(args[0].lower()):
		myverb = v
		args.popleft()
		break
if not myverb:
	print "Did not specify a verb!"
	exit(1)

for n in verbmap[myverb]:
	if n.startswith(args[0].lower()):
		mynoun = n
		args.popleft()
		break
if not mynoun and verbmap[myverb]:
	print "Could not find a noun for {0}".format(myverb);
	exit(1)

configfile = open(opts.configfile, 'r')
config = json.load(configfile)
configfile.close()
if('cli' not in config or 'reply' not in config['cli'] or
	'pull' not in config['cli']):
	print "Could not find cli configuration in configuration file"
	exit(1)

ctx = zmq.Context()
reqsock = ctx.socket(zmq.REQ)
reqsock.connect(config['cli']['reply'])
pushsock = ctx.socket(zmq.PUSH)
pushsock.connect(config['cli']['pull'])

services = dict()
hosts = dict()
contactgroups = set([ ])

def handle_notifications(verb, obj):
	cmd = { 'host_name':obj['host_name'], 'type':'command' }
	name = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
		name = obj['service_description'] + '@' + name
		cmd['command_name'] = verb + '_service_notifications'
	else:
		cmd['command_name'] = verb + "_host_notifications"
	if(verb == 'enable' and obj['notifications_enabled']):
		print "[{0}]: Notifications already enabled".format(name)
		return
	elif(verb == 'disable' and not obj['notifications_enabled']):
		print "[{0}]: Notifications already disabled".format(name)
		return
	pushsock.send_json(cmd)
	print "[{0}]: Notifications {1}".format(name, pasttenses[verb])

def handle_checks(verb, obj):
	cmd = { 'host_name':obj['host_name'], 'type':'command' }
	name = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
		name = obj['service_description'] + '@' + name
		cmd['command_name'] = verb + "_service_checks"
	else:
		cmd['command_name'] = verb + "_host_checks"
	if(verb == 'enable' and obj['checks_enabled']):
		print "[{0}]: Checks already enabled".format(name)
		return
	elif(verb == 'disable' and not obj['checks_enabled']):
		print "[{0}]: Checks already disabled".format(name)
		return
	pushsock.send_json(cmd)
	print "[{0}]: Checks {1}".format(name, pasttenses[verb])

def handle_acknowledgement(verb, obj):
	name = obj['host_name']
	if('service_description' in obj):
		name = obj['service_description'] + '@' + name
	if(verb == 'add'):
		if(obj['current_state'] == 0):
			print "[{0}]: No problem found".format(name)
			return
		elif(obj['problem_has_been_acknowledged']):
			print "[{0}]: Problem already acknowledged".format(name)
			return
		cmd = { 'type': 'acknowledgement',
			'author_name':username, 'comment_data': opts.comment,
			'time_stamp': { 'tv_sec': time.time() },
			'notify_contacts': opts.notify,
			'persistent_comment': opts.persistent }
	elif(verb == 'remove'):
		if(not obj['problem_has_been_acknowledged']):
			print "[{0}]: No acknowledgement to remove".format(name)
			return
		cmd = { 'type': 'command' }
		if('service_description' in obj):
			cmd['command_name'] = 'remove_service_acknowledgement'
		else:
			cmd['command_name'] = 'remove_host_acknowledgement'
	cmd['host_name'] = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
	pushsock.send_json(cmd)
	print "[{0}]: Acknowledgement {1}".format(name, pasttenses[verb])

def handle_comment(verb, obj):
	cmd = { 'type': 'comment_add', 'host_name':obj['host_name'],
		'author_name':username, 'comment_data': opts.comment,
		'time_stamp': { 'tv_sec': time.time() },
		'persistent_comment': opts.persistent }
	name = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
		name = obj['service_description'] + '@' + name
	if(verb != 'add'):
		print '[{0}]: Cannot {1} comments!'.format(name, verb)
		return
	pushsock.send_json(cmd)
	print "[{0}]: Comment {1}".format(name, pasttenses[verb])

def handle_eventhandler(verb, obj):
	cmd = { 'host_name':obj['host_name'], 'type':'command' }
	name = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
		name = obj['service_description'] + '@' + name
		cmd['command_name'] = verb + "_service_event_handler"
	else:
		cmd['command_name'] = verb + "_host_event_handler"
	if(verb == 'enable' and obj['event_handler_enabled']):
		print "[{0}]: Event handler already enabled".format(name)
		return
	elif(verb == 'disable' and not obj['event_handler_enabled']):
		print "[{0}]: Event handler already disabled".format(name)
		return
	pushsock.send_json(cmd)
	print "[{0}]: Event handler {1}".format(name, pasttenses[verb])

def rm_downtime(obj):
	cmd = { 'host_name':obj['host_name'], 'type':'command',
		'command_name': 'delete_downtime' }
	name = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
		name = obj['service_description'] + '@' + name
	pushsock.send_json(cmd)
	print "[{0}]: Removing downtime".format(name)

def add_downtime(obj):
	cmd = { 'host_name':obj['host_name'], 'type':'downtime_add',
		'author_name':username, 'comment_data': opts.comment,
		'entry_time': int(time.time()) , 'fixed': opts.flexible == 0 }
	name = obj['host_name']
	if('service_description' in obj):
		cmd['service_description'] = obj['service_description']
		name = obj['service_description'] + '@' + name

	starttime, endtime, duration = tuple([None] * 3)
	if(opts.starttime):
		starttime = datetime.strptime(opts.starttime, '%m-%d %H:%M')
	else:
		starttime = datetime.now()

	if(opts.duration):
		dr = re.match('^(\d+)(m|h|d)?$', opts.duration)
		if(dr.group(2)):
			val = int(dr.group(1))
			if(dr.group(2) == 'm'):
				duration = timedelta(minutes=val)
			elif(dr.group(2) == 'h'):
				duration = timedelta(hours=val)
			elif(dr.group(2) == 'd'):
				duration = timedelta(days=val)
		elif(dr.group(1)):
			duration = timedelta(minutes=int(dr.group(1)))
		else:
			print "[{0}]: Format error for duration!".format(name)
			return
		endtime = starttime + duration
	elif(opts.endtime):
		endtime = datetime.strptime(opts.endtime, '%m-%d %H:%M')
		duration = endtime - starttime

	cmd['start_time'] = int(time.mktime(starttime.timetuple()))
	cmd['end_time'] = int(time.mktime(endtime.timetuple()))
	cmd['duration'] = duration.seconds
	cmd['triggered_by'] = 0
	
	pushsock.send_json(cmd)
	print "[{0}]: Adding {1}downtime for {2}".format(name, 'flexible ' if opts.flexible else '', str(duration))

def handle_downtime(verb, obj):
	if(verb == 'add'):
		add_downtime(obj)
	elif(verb == 'remove'):
		rm_downtime(obj)
	
nounmap = {
	'notifications': handle_notifications,
	'checks': handle_checks,
	'acknowledgement': handle_acknowledgement,
	'comment': handle_comment,
	'downtime': handle_downtime,
	'eventhandler': handle_eventhandler }

def is_authorized(o):
	if(os.getuid() == 0):
		return True
	if(o['contacts'] and username in o['contacts']):
		return True
	if(len(contactgroups.intersection(set(o['contact_groups']))) > 0):
		return True
	return False

def parse_object(o, svcname):
	if(o['type'] == 'host'):
		if(o['host_name'] in hosts):
			return
		if(not is_authorized(o)):
			return
		if(not svcname):
			hosts[o['host_name']] = o
		if(not o['services'] or opts.hostsonly):
			return
		for s in o['services']:
			if(svcname and s != svcname):
				continue
			reqsock.send_json( {
				'host_name': o['host_name'],
				'service_description': s,
				'keys': keys } )
			for so in json.loads(reqsock.recv()):
				parse_object(so, svcname)
	elif(o['type'] == 'service' and not opts.hostsonly):
		if(svcname and svcname != o['service_description']):
			return
		name = "{0}@{1}".format(o['service_description'], o['host_name'])
		if(name in services):
			return
		if(not is_authorized(o)):
			return
		services[name] = o

username = pwd.getpwuid(os.getuid())[0]
if(os.getuid() != 0):
	reqsock.send_json( {
		'contact_name': username,
		'keys': ['contact_groups', 'type', 'name'] } )
	for o in json.loads(reqsock.recv()):
		if(o['type'] == 'contact'):
			contactgroups = set(o['contact_groups'])
			break
	
for td in args:
	tm = re.match(r'([^\@]+)?\@?([^\s]+)?', td)
	p1, p2 = tm.group(1), tm.group(2)
	if(not p2):
		reqsock.send_json( {
			'host_name': p1,
			'include_services': True,
			'keys': keys } )
		for o in json.loads(reqsock.recv()):
			parse_object(o, None)

		if(len(services) > 0 or len(hosts) > 0):
			continue

		reqsock.send_json( {
			'hostgroup_name': p1,
			'include_hosts': True,
			'keys': keys } )
		for o in json.loads(reqsock.recv()):
			parse_object(o, None)

		if(len(services) > 0 or len(hosts) > 0):
			continue
		reqsock.send_json( {
			'list_services': p1,
			'expand_lists': True,
			'include_hosts': True,
			'keys': keys } )
		for o in json.loads(reqsock.recv()):
			parse_object(o, p1)
	else:
		reqsock.send_json( {
			'host_name': p2,
			'service_description': p1,
			'keys': keys } )
		for o in json.loads(reqsock.recv()):
			parse_object(o, p1)

		if(len(services) > 0):
			continue
		reqsock.send_json( {
			'hostgroup_name': p2,
			'include_hosts': True,
			'keys': keys } )
		for o in json.loads(reqsock.recv()):
			parse_object(o, p1)

if(len(services) == 0 and len(hosts) == 0):
	print "No services or hosts matched the target criteria"
	exit(2)

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
hosts_printed = { }
for s in sorted(services.keys()):
	so = services[s]
	if(so['host_name'] not in hosts_printed and
		so['host_name'] in hosts):
		h = hosts[so['host_name']]
		if(myverb == 'status'):
			print "[{0}]: {1} {2}".format(
				h['host_name'],
				status_to_string(h['current_state'], True),
				h['plugin_output'])
		hosts_printed[h['host_name']] = True
		if(mynoun):
			nounmap[mynoun](myverb, h)
	if(myverb == 'status'):
		print "[{0}]: {1} {2}".format(
			s, status_to_string(so['current_state'], False),
			so['plugin_output'])
	if(mynoun):
		nounmap[mynoun](myverb, services[s])

if(len(services.keys()) > 0):
	exit(0)

for h in sorted(hosts.keys()):
	ho = hosts[h]
	if myverb == 'status':
		print "[{0}]: {1} {2}".format(
			ho['host_name'],
			status_to_string(ho['current_state'], True),
			ho['plugin_output'])
	elif mynoun:
		nounmap[mynoun](myverb, ho)

exit(0)
