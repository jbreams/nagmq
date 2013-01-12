import zmq, simplejson as json, time

zctx = zmq.Context()

jobs = zctx.socket(zmq.PULL)
jobs.connect("ipc:///var/nagios/mqexecjobs.sock")
results = zctx.socket(zmq.PUSH)
results.connect("ipc:///var/nagios/mqexecresults.sock")

while True:
	job = jobs.recv()
	if jobs.getsockopt(zmq.RCVMORE) > 0:
		continue
	
	job = json.loads(job)

	keys = [ "host_name", "service_description",
		"check_options", "scheduled_check", "reschedule_check",
		"latency", "early_timeout", "check_type" ]
	out = { }
	for k in keys:
		if k not in job:
			continue
		out[k] = job[k]

	out['scheduled_check'] = 1
	out['reschedule_check'] = 1
	out['output'] = "Test! Test! Test!\n"
	out['return_code'] = 0
	out['exited_ok'] = 1
	out['early_timeout'] = 0
	now = int(time.time())
	out['start_time'] = { 'tv_sec': now, 'tv_usec': 0 }
	out['finish_time'] = { 'tv_sec': now, 'tv_usec': 500 }
	out['type'] = 'service_check_processed' if 'service_description' in job \
		else 'host_check_processed'

	results.send(json.dumps(out))
