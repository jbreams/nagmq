import zmq, time, json, hashlib

class haloop:
	_meventa = ""
	_mstatea = ""
	_ctx = None

	_lostate = None
	_locmd = None
	_loevents = None

	_meventsubs = [ 'program_status', 'host_check_processed',
		'service_check_processed', 'downtime_add', 'comment_add',
		'acknowledgement', 'adaptiveservice_update', 'adaptivehost_update' ]

	def __init__(self, meventa, mstatea, leventa, lcmda, lstatea, ctx = None):
		if not ctx:
			ctx = zmq.Context()
			
		self._meventa = meventa
		self._mstatea = mstatea

		lostate = ctx.socket(zmq.REQ)
		locmd = ctx.socket(zmq.PUSH)
		loevents = ctx.socket(zmq.SUB)

		lostate.connect(lstatea)
		locmd.connect(lcmda)
		loevents.connect(leventa)
		loevents.setsockopt(zmq.SUBSCRIBE, 'program_status')

		self._lostate = lostate
		self._locmd = locmd
		self._loevents = loevents

		self._ctx = ctx

	def send_nagios_commands(*cmds):
		for c in cmds:
			cmd = { 'type': 'command', 'command_name': c }
			self._locmd.send(json.dumps(cmd))
		return True

	def _hash_downtime(obj):
		rethash = hashlib.sha1()
		for k in [ 'host_name', 'service_description', 'start_time',
			'end_time', 'fixed', 'duration', 'author_name', 'comment_data' ]:
			rethash.update(str(obj[k]))
		return rethash.digest()

	def _hash_comment(obj):
		rethash = hashlib.sha1()
		for k in [ 'host_name', 'service_description', 'author_data', 'comment_data',
			'expires', 'expire_time', 'persistent', 'source', 'entry_type' ]:
			rethash.update(str(obj[k]))
		return rethash.digest()

	def resolve_diffs(self, timeout):
		castate = self._ctx.socket(zmq.REQ)
		castate.connect(self._mstatea)

		self._lostate.send(json.dumps({'list_downtimes': True }))
		lodowntimes = set()
		for d in json.loads(self._lostate.recv()):
			lodowntimes.add(hash_downtime(d))

		if castate.poll(timeout=timeout, flags=zmq.POLLOUT) == 0:
			castate.close()
			return False
		
		castate.send(json.dumps({'list_downtimes': True }))
		for d in json.loads(castate.recv()):
			dh = self._hash_downtime(d)
			if dh in lodowntimes:
				continue
			self._locmd.send(json.dumps(d))

		self._lostate.send(json.dumps({'list_comments': True }))
		locomments = set()
		for c in json.loads(self._lostate.recv()):
			locomments.add(hash_downtime(c))

		castate.send(json.dumps({'list_comments': True }))
		for c in json.loads(castate.recv()):
			ch = self._hash_downtime(c)
			if ch in locomments:
				continue
			self._locmd.send(json.dumps(c))

		castate.send(json.dumps({ 'list_hosts': True, 'expand_lists': True,
			'include_services': True, 'keys': [ 'host_name', 'service_description',
			'plugin_output', 'long_output', 'perf_data', 'current_state',
			'current_attempt', 'state_type', 'is_flapping', 'notifications_enabled',
			'checks_enabled', 'event_handler_enabled', 'flap_detection_enabled',
			'problem_has_been_acknowledged', 'accept_passive_service_checks',
			'accept_passive_host_checks', 'type' ] }))

		state_data = json.loads(castate.recv())
		self._locmd.send(json.dumps({'type': 'state_data', 'data': state_data }))

		castate.close()
		return True

	# This should be overwritten to become the passive node in your environment.
	def become_passive(self):
		pass

	def passive_loop(self, timeout):
		if not self.resolve_diffs():
			return False

		if not self.become_passive():
			return False

		caevents = self._ctx.socket(zmq.SUB)
		caevents.connect(self._meventsa)
		for s in self._meventsubs:
			caevents.setsockopt(zmq.SUBSCRIBE, s)

		while caevents.poll(timeout=timeout) != 0:
			typemsg, pmsg = caevents.recv_multipart()
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
				self._locmd.send(json.dumps(out))

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
					nku = cmd_map[k][0] if payload[k] else cmd_map[k][1]
					nk = nku % 'service' if 'service_description' in out else 'host'
					out['command_name'] = nk
					break
				self._locmd.send(json.dumps(out))

			elif typemsg == 'program_status':
				continue
			else:
				self._locmd.send(pmsg)

		caevents.close()
		return True

	# This should be overwritten to become the active node in your environment.
	def become_active(self):
		pass

	def active_loop(self, timeout):
		if not self.become_active():
			return False

		while self._loevents.poll(timeout=timeout) != 0:
			tmsg, pmsg = self._loevents.recv_multipart()
			pass

		return True

