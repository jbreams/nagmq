import zmq, time, simplejson as json, hashlib, subprocess
zctx = zmq.Context()

casub_addr = "tcp://tcpaddress"
# These are the types of events that will be passed off to the local Nagios process
casub_subs = [ 'program_status', 'host_check_processed',
	'service_check_processed', 'downtime_add', 'comment_add', 'acknowledgement',
	'adaptiveservice_update', 'adaptivehost_update' ]
careq_addr = "tcp://tcpaddress"

loreq = zctx.socket(zmq.REQ)
loreq.connect("ipc://ipcaddress")

lopush = zctx.socket(zmq.PUSH)
lopush.connect("ipc://ipcaddress")

# 3 minutes in milliseconds
master_timeout = 180000

# Site specific variables for bringing up active node vif
active_vifip = "vifaddress"
active_vifif = "bond0"

# These functions are site specific, they should do any extra work needed
# to become an active or a passive node and then send the appropriate
# commands to Nagios to start and stop events
def become_active():
	vifcmd = "/sbin/ip addr add {0} dev {1}".format(active_vifip, active_vifif)
	if subprocess.call(vifcmd) != 0:
		return False

	if subprocess.call("/sbin/service nagios status") == 1:
		if subprocess.call("/sbin/service nagios start") != 0:
			return False

	if subprocess.call("/sbin/service mqbroker restart") != 0:
		return False
	
	cmds = [ 'enable_all_notifications', 'start_executing_host_checks',
		'start_executing_service_checks', 'start_using_event_handlers' ]
	for c in cmds:
		cmd = { 'type': 'command', 'command_name': c }
		lopush.send(json.dumps(cmd))
	return True

def become_passive():
	vifcmd = "/sbin/ip addr del {0} dev {1}".format(active_vifip, active_vifif)
	print vifcmd
	if subprocess.call(vifcmd) != 0:
		return False
	if subprocess.call("/sbin/service nagios status") == 1:
		if subprocess.call("/sbin/service nagios start") != 0:
			return False

	if subprocess.call("/sbin/service mqbroker restart") != 0:
		return False

	cmds = [ 'disable_all_notifications', 'stop_executing_host_checks',
		'stop_executing_service_checks', 'stop_using_event_handlers' ]
	for c in cmds:
		cmd = { 'type': 'command', 'command_name': c }
		lopush.send(json.dumps(cmd))
	return True

# These functions are re-usable for most if not all sites.
def hash_downtime(obj):
	rethash = hashlib.sha1()
	for k in [ 'host_name', 'service_description', 'start_time',
		'end_time', 'fixed', 'duration', 'author_name', 'comment_data' ]:
		rethash.update(str(obj[k]))
	return rethash.digest()

def hash_comment(obj):
	rethash = hashlib.sha1()
	for k in [ 'host_name', 'service_description', 'author_data', 'comment_data',
		'expires', 'expire_time', 'persistent', 'source', 'entry_type' ]:
		rethash.update(str(obj[k]))
	return rethash.digest()

def resolve_diffs():
	careq = zctx.socket(zmq.REQ)
	careq.connect(careq_addr)

	loreq.send(json.dumps({'list_downtimes': True }))
	lodowntimes = set()
	for d in json.loads(loreq.recv()):
		lodowntimes.add(hash_downtime(d))

	if careq.poll(timeout=master_timeout, flags=zmq.POLLOUT) == 0:
		careq.close()
		return False
	
	careq.send(json.dumps({'list_downtimes': True }))
	for d in json.loads(careq.recv()):
		dh = hash_downtime(d)
		if dh in lodowntimes:
			continue
		lopush.send(json.dumps(d))

	loreq.send(json.dumps({'list_comments': True }))
	locomments = set()
	for c in json.loads(loreq.recv()):
		locomments.add(hash_downtime(c))

	careq.send(json.dumps({'list_comments': True }))
	for c in json.loads(careq.recv()):
		ch = hash_downtime(c)
		if ch in locomments:
			continue
		lopush.send(json.dumps(c))

	careq.send(json.dumps({ 'list_hosts': True, 'expand_lists': True,
		'include_services': True, 'keys': [ 'host_name', 'service_description',
		'plugin_output', 'long_output', 'perf_data', 'current_state',
		'current_attempt', 'state_type', 'is_flapping', 'notifications_enabled',
		'checks_enabled', 'event_handler_enabled', 'flap_detection_enabled',
		'problem_has_been_acknowledged', 'accept_passive_service_checks',
		'accept_passive_host_checks', 'type' ] }))

	state_data = json.loads(careq.recv())
	lopush.send(json.dumps({'type': 'state_data', 'data': state_data }))

	careq.close()
	return True

def passive_loop():
	if not resolve_diffs():
		return

	if not become_passive():
		return
	casub = zctx.socket(zmq.SUB)
	casub.connect(casub_addr)
	for s in casub_subs:
		casub.setsockopt(zmq.SUBSCRIBE, s)

	last_programstatus = None

	while casub.poll(timeout=master_timeout) != 0:
		typemsg, pmsg = casub.recv_multipart()
		payload = json.loads(pmsg)
		if typemsg in set('service_check_processed', 'host_check_processed'):
			out = { }
			tocopy = [ 'host_name', 'service_description', 'return_code',
				'start_time', 'finish_time', 'latency', 'early_timeout' ]
			for k in tocopy:
				if k in payload:
					out[k] = payload[k]
			out['check_options'] = 0
			out['check_type'] = 1
			out['exited_ok'] = 1
			out['scheduled_check'] = 1
			out['reschedule_check'] = 1

			final_output = str()
			if payload['perf_data']:
				final_output = "{0}|{1}\n".format(
					payload['output'], payload['perf_data'])
			else:
				final_output = "{0}\n".format(payload['output'])
			if payload['long_output']:
				final_output += payload['long_output']

			out['output'] = final_output
			lopush.send(json.dumps(out))
		elif typemsg in set('adaptivehost_update', 'adaptiveservice_update'):
			out = { 'type': 'command' }
			for k in [ 'host_name', 'service_description' ]:
				if k in payload:
					out[k] = payload[k]

			cmd_map = { 'notifications_enabled':
					[ 'enable_%s_notifications', 'disable_%s_notifications' ],
				'checks_enabled':
					[ 'enable_%s_checks', 'disable_%s_checks' ],
				'accept_passive_service_checks':
					[ 'enable_passive_%s_checks', 'disable_passive_%s_checks' ],
				'accept_passive_host_checks':
					[ 'enable_passive_%s_checks', 'disable_passive_%s_checks' ],
				'event_handler_enabled':
					[ 'enable_%s_event_handler', 'enable_%s_event_handler' ],
				'obsess_over_service':
					[ 'start_obsessing_over_%s', 'stop_obsessing_over_%s' ],
				'obsess_over_host':
					[ 'start_obsessing_over_%s', 'stop_obsessing_over_%s' ]
			}
				
			for k in cmd_map:
				if k not in payload:
					continue
				nku = payload[k] ? cmd_map[k][0] : cmd_map[k][1]
				nk = nku % 'service_description' in out ? 'service' : 'host'
				out['command_name'] = nk
				break
		elif typemsg == 'program_status':
			continue
		else:
			lopush.send(pmsg)

	casub.close()

def active_loop():
	losub = zctx.socket(zmq.SUB)
	losub.connect(losub_addr)
	losub.setsockopt(zmq.SUBSCRIBE, 'program_status')

	if not become_active():
		return

	while losub.poll(timeout=master_timeout) != 0:
		pass

	losub.close()

while True:
	passive_loop()
	active_loop()	
