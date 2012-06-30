#!/usr/bin/python26
 
import time, zmq, os, cgi, json

zctx = zmq.Context()
req = zctx.socket(zmq.REQ)
req.connect("tcp://localhost:5557")

configfile = open('/etc/nagios/nagmq.conf', 'r')
config = json.load(configfile)
configfile.close()
config = config['cgi']

print 'Content-Type: application/json'
print

user = os.environ['REMOTE_USER']
params = cgi.parse()
include_output = False
just_count = False

if 'include_output' in params and params['include_output']:
	include_output = True
if 'just_count' in params and params['just_count']:
	just_count = True

def resolve_user(username, contactgroup):
	req.send_json( { 'contactgroup_name': contactgroup,
		'keys': [ 'type', 'members' ] } )
	res = req.recv_json()
	if len(res) == 0:
		return False
	res = res[0]
	if res['type'] != 'contactgroup':
		return False
	if user not in set(res['members']):
		return False
	return True

if config and 'administrators' in config:
	if resolve_user(user, config['administrators']):
		user = None
elif config and 'readonly' in config:
	if resolve_user(user, config['readonly']):
		user = None

reqobj = { keys: [ 'type', 'host_name', 'current_state', 
	'service_description', 'has_been_checked' ], 
	'include_hosts': True, 'include_services': True }

if user:
	reqobj['for_user'] = user

if params['hostgroup_name']:
	reqobj['hostgroup_name'] = params['hostgroup_name']
elif params['servicegroup_name']:
	reqobj['servicegroup_name'] = params['servicegroup_name']
else:
	reqobj['list_hosts'] : True
	reqobj['list_services'] : True
	reqobj['expand_lists'] : True
if include_output:
	reqobj['keys'].append('output')

req.send_json(reqobj)
res = req.recv_json()

def build_result():
	res = [ ]
	for x in range(0, 4):
		if include_output:
			res[x] = { }
		elif just_count:
			res[x] = 0
		else:
			res[x] = [ ]
	return res

hosts = build_result()
services = build_result()

def add_entry(obj):
	global hosts, services
	if obj['type'] == 'service':
		if not obj['has_been_checked']:
			obj['current_state'] = 4
		name = '{0}@{1}'.format(
			obj['service_description'], obj['host_name'])
		if include_output:
			services[obj['current_state']][name] = obj['output']
		elif just_count:
			services[obj['current_state']] += 1
		else:
			services[obj['current_state']].append(name)
	elif obj['type'] == 'host':
		if not obj['has_been_checked']:
			obj['current_state'] = 4
		if include_output:
			hosts[obj['current_state']][obj['host_name'] = obj['output']
		elif just_count:
			hosts[obj['current_state']] += 1
		else:
			hosts[obj['current_state']].append(obj['host_name'])

for o in res:
	add_entry(o)

output = { 'hosts': { 'UP': hosts[0], 'DOWN': hosts[1],
	'UNREACHABLE': hosts[2], 'PENDING': hosts[4] },
	'services': { 'OK': services[0], 'WARNING': services[1],
	'CRITICAL': services[2], 'UNKNOWN': services[3],
	'PENDING': services[4] } }

json.dumps(output)
exit(0)
