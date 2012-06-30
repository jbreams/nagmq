#!/usr/bin/python26
 
import time, zmq, os, cgi, json

zctx = zmq.Context()
req = zctx.socket(zmq.REQ)
req.connect("tcp://localhost:5557")

configfile = open('/etc/nagios/nagmq.conf', 'r')
config = json.load(configfile)
configfile.close()
config = config['cgi'] if 'cgi' in config else None

user = os.environ['REMOTE_USER']
params = cgi.parse()

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

def dedup(k):
	global params
	params[k] = params[k][0]
map(dedup, params)

if user:
	params['for_user'] = user
req.send_json(params)

print 'Content-Type: application/json'
print
print req.recv()
exit(0)
