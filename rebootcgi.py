#!/usr/bin/python26
"""
This is a CGI that will add 20 minutes of downtime for whatever host
accesses it. It's intended to be called from the shutdown scripts of
hosts, so that hosts that are being shut down in a controlled manner
don't cause spurious alerts.
"""

import time, zmq, os, socket
from datetime import timedelta, datetime

print "Content-Type: text/html"
print

zctx = zmq.Context()
push = zctx.socket(zmq.PUSH)
push.connect("tcp://localhost:5556")
req = zctx.socket(zmq.REQ)
req.connect("tcp://localhost:5557")

start_time = int(time.time())
end_time = start_time + timedelta(minutes=15).seconds
hostname, aliaslist, iplist = socket.gethostbyaddr(os.environ['REMOTE_ADDR'])

def resolve_name(name):
	cmd = { 'host_name': name,
		'keys': [ 'type', 'host_name' ] }
	req.send_json(cmd)
	ret = req.recv_json()
	for o in ret:
		if o['type'] == 'host':
			return o['host_name']
	return None

def resolve_fullname(name):
	parts = name.split('.')
	highpart = 0
	while highpart < len(parts):
		name = resolve_name('.'.join(parts[0:highpart]))
		if name:
			break
		highpart += 1
	return name

realname = resolve_fullname(hostname)
if not realname:
	for name in aliaslist:
		realname = resolve_fullname(name)
		if realname:
			break

if not realname:
	print "Error finding matching hostname!!"
	exit(1)

cmd = { 'host_name': realname, 'type':'downtime_add',
	'author_name':'reboot', 'comment_data': 'Downtime during reboot',
	'entry_time': int(time.time()), 'fixed': True,
	'start_time': start_time, 'end_time': end_time,
	'duration': end_time - start_time, 'triggered_by': 0 }
push.send_json(cmd)
exit(0)

