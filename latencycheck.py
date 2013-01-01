import zmq, time, simplejson as json
context = zmq.Context()

pub = context.socket(zmq.REQ)
pub.connect("ipc:///var/nagios/nagmqstate.sock")
start = time.time()

def get_latency():
	now = time.time()
	pub.send_json({ "list_hosts": True, "include_services": True, "keys": [ "latency", "type" ], "expand_lists": True})
	respraw = pub.recv()
	end = time.time()
	resp = json.loads(respraw)

	svc_latency_max = 0
	svc_latency_avg = 0
	svcs_count = 0
	host_latency_max = 0
	host_latency_avg = 0
	hosts_count = 0

	for obj in resp:
		if obj['type'] == 'service':
			svc_latency_max = max(svc_latency_max, obj['latency'])
			svc_latency_avg += obj['latency']
			svcs_count += 1
		elif obj['type'] == 'host':
			host_latency_max = max(host_latency_max, obj['latency'])
			host_latency_avg += obj['latency']
			hosts_count += 1

	svc_latency_avg /= svcs_count
	host_latency_avg /= hosts_count

	print "{0} {1} {2} {3} {4} {5}".format(now - start, end - now, svc_latency_max, svc_latency_avg, host_latency_max, host_latency_avg)

while time.time() - start < 60 * 60:
	get_latency()
