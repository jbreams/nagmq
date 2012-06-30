#!/usr/bin/python26
 
import time, zmq, os, cgi
from datetime import timedelta, datetime

zctx = zmq.Context()
push = zctx.socket(zmq.PUSH)
push.connect("tcp://localhost:5556")
req = zctx.socket(zmq.REQ)
req.connect("tcp://localhost:5557")

configfile = open('/etc/nagios/nagmq.conf', 'r')
config = json.load(configfile)
configfile.close()
config = config['cgi']

print 'Content-Type: application/json'
print

user = os.environ['REMOTE_USER']
rawparams = cgi.FieldStorage()
params = { }
for k in rawparams.keys()
	params[k] = rawparams.getfirst(k)

if 'service_description' in params:
	req.send_json({ 'host_name': params['host_name'],
		'service_description': params['service_description'],
		'for_user': user, 'keys': [ 'type' ] })
	res = req.recv_json()
	if len(res) == 0 or res[0]['type'] == 'error':
		print json.dumps( { "result": "{0} not authorized for {1}@{2}".format(
			user, params['service_description'],
			params['host_name'])})
		exit(0)
elif 'host_name' in params:
	req.send_json({ 'host_name': params['host_name'],
		'for_user': user, 'keys': [ 'type' ] })
	res = req.recv_json()
	if len(res) == 0 or res[0]['type'] == 'error':
		print json.dumps({ "result": "{0} not authorized for {1}".format(
			user, params['host_name'])})
		exit(0)
elif config and 'administrators' in config:
	req.send_json( { 'contactgroup_name': config['administrators'],
		'keys': [ 'type', 'members' ] } )
	res = req.recv_json()
	if len(res) == 0 or res[0]['type'] == 'error'
		print json.dumps( { "result": "Could not find administrators group {0}".format(
			config['administrators']) } )
		exit(0)
	if user not in set(res[0]['members']):
		print json.dumps( { "result": "{0} is not an administrator".format(user) } )
		exit(0)
else:
	print json.dumps( { "result": "No authorization data. Cannot continue." } )
	exit(0)

push.send_json(params)
print json.dumps( { "result": "Command sent" } )
exit(0)
