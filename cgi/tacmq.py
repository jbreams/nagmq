#!/usr/bin/python26
 
import time, zmq, os, cgi, json, cgitb
cgitb.enable()

zctx = zmq.Context()
req = zctx.socket(zmq.REQ)
req.connect("tcp://localhost:5557")

configfile = open('/etc/nagios/nagmq.conf', 'r')
config = json.load(configfile)
configfile.close()
config = config['cgi'] if 'cgi' in config else None

user = os.environ['REMOTE_USER']
params = cgi.parse()
include_output = False
just_count = False

host_latency = { 'min': float('inf'), 'max': 0, 'average': 0 }
host_execution_times = { 'min': float('inf'), 'max': 0, 'average': 0 }
service_latency = { 'min': float('inf'), 'max': 0, 'average': 0 }
service_execution_times = { 'min': float('inf'), 'max': 0, 'average': 0 }

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

reqobj = { 'keys': [ 'type', 'host_name', 'current_state', 
	'service_description', 'has_been_checked', 'latency',
	'execution_time' ] }

if user:
	reqobj['for_user'] = user

if 'hostgroup_name' in params:
	reqobj['hostgroup_name'] = params['hostgroup_name']
	reqobj['include_services'] = True
elif 'servicegroup_name' in params:
	reqobj['servicegroup_name'] = params['servicegroup_name']
	reqobj['include_hosts'] = True
else:
	reqobj['list_hosts'] = True
	reqobj['list_services'] = True
	reqobj['expand_lists'] = True
if include_output:
	reqobj['keys'].append('plugin_output')

req.send_json(reqobj)
res = req.recv_json()

def build_result():
	if include_output:
		return [{},{},{},{},{}]
	elif just_count:
		return [0, 0, 0, 0, 0]
	else:
		return [[],[],[],[],[]]

hosts = build_result()
services = build_result()
nhosts, nservices = 0, 0

def add_entry(obj):
	global hosts, services, host_latency, host_execution_times,
		nhosts, nservices
	if obj['type'] == 'service':
		state = obj['current_state']
		if not obj['has_been_checked']:
			state = 4
		name = '{0}@{1}'.format(
			obj['service_description'], obj['host_name'])
		if include_output:
			services[state][name] = obj['plugin_output']
		elif just_count:
			services[state] += 1
		else:
			services[state].append(name)
		service_execution_times['min'] = min(
			service_execution_times['min'], obj['execution_time'])
		service_execution_times['max'] = max(
			service_execution_times['min'], obj['execution_time'])
		service_execution_times['average'] += obj['execution_time'];
		service_latency['min'] = min(service_latency['min'], obj['latency'])
		service_latency['max'] = max(service_latency['max'], obj['latency'])
		service_latency['average'] += obj['latency']
		nservices += 1
		
	elif obj['type'] == 'host':
		state = obj['current_state']
		if not obj['has_been_checked']:
			state = 4
		if include_output:
			hosts[state][obj['host_name']] = obj['plugin_output']
		elif just_count:
			hosts[state] += 1
		else:
			hosts[state].append(obj['host_name'])
		host_execution_times['min'] = min(host_execution_times['min'],
			obj['execution_time'])
		host_execution_times['max'] = max(host_execution_times['min'],
			obj['execution_time'])
		host_execution_times['average'] += obj['execution_time'];
		host_latency['min'] = min(host_latency['min'], obj['latency'])
		host_latency['max'] = max(host_latency['max'], obj['latency'])
		host_latency['average'] += obj['latency']
		nhosts += 1

map(add_entry, res)

service_latency['average'] /= nservices
service_execution_times['average'] /= nservices
host_latency['average'] /= nhosts
host_execution_times['average'] /= nhosts

output = { 'hosts': { 'UP': hosts[0], 'DOWN': hosts[1],
	'UNREACHABLE': hosts[2], 'PENDING': hosts[4],
	'latency': host_latency, 'execution_time': host_execution_times },
	'services': { 'OK': services[0], 'WARNING': services[1],
	'CRITICAL': services[2], 'UNKNOWN': services[3],
	'PENDING': services[4], 'latency': service_latency,
	'execution_time', service_execution_times } }
print 'Content-Type: application/json'
print
print json.dumps(output)
exit(0)
