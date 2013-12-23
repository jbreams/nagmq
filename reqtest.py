import zmq, time, json
context = zmq.Context()

pub = context.socket(zmq.REQ)

# These are random useless keys for testing Curve auth
pubkey = u"7d0:tz+tGVT&*ViD/SzU)dz(3=yIE]aT2TRNrG2$"
privkey = u"FCFo%:3pZTbiQq?MARHYk(<Kp*B-<RpRG7QMUlXr"
serverkey = u"mN>y$-+17hxa6F>r@}sxmL-uX}IM=:wIq}G4y*f["

pub.setsockopt_string(zmq.CURVE_PUBLICKEY, pubkey)
pub.setsockopt_string(zmq.CURVE_SECRETKEY, privkey)
pub.setsockopt_string(zmq.CURVE_SERVERKEY, serverkey)

pub.connect("tcp://localhost:5557")
keys = ['host_name', 'services', 'hosts', 'contacts', 'contact_groups',
        'service_description', 'current_state', 'members', 'type', 'name',
        'problem_has_been_acknowledged', 'plugin_output' ]
pub.send_json({ "host_name": "localhost", "include_services": True, "include_contacts": True, 'keys': keys })
resp = json.loads(pub.recv())
def status_to_string(val, ishost):
	if(ishost):
		if(val < 2):
			return "UP"
		else:
			return "DOWN"
	else:
		if(val == 0):
			return "OK"
		elif(val == 1):
			return "WARNING"
		elif(val == 2):
			return "CRITICAL"
		elif(val == 3):
			return "UNKNOWN"

for obj in resp:
	if(obj['type'] == 'service'):
		print "{0}@{1}: {2} {3}".format(
			obj['service_description'], obj['host_name'],
			status_to_string(obj['current_state'], 0), obj['plugin_output'])
	elif(obj['type'] == 'host'):
		print "{0}: {1} {2}".format(
			obj['host_name'], status_to_string(obj['current_state'], 1),
			obj['plugin_output'])
	elif(obj['type'] == 'error'):
		print obj['msg']
	elif(obj['type'] == 'service_list'):
		print obj['services']
