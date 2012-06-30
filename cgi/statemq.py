#!/usr/bin/python26
 
import time, zmq, os, cgi

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

if user:
	params['for_user'] = user
req.send_json(params)
print req.recv()
exit(0)
