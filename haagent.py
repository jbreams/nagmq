import time, halib, subprocess as proc

active_vifip = "ipaddress"
active_vifif = "bond0"

master_eventsa = "tcp://ipaddr:port"
master_statea = "tcp://ipcaddr:port"

local_eventsa = "ipc://path"
local_statea = "ipc://path"
local_cmda = "ipc://path"

timeout = 180000

class haagent(halib.haloop):
	def become_passive(self):
		vifcmd = "/sbin/ip addr del {0} dev {1}".format(active_vifip, active_vifif)

		if proc.call(vifcmd) != 0:
			return False
		if proc.call("/sbin/service nagios status") == 1:
			if subprocess.call("/sbin/service nagios start") != 0:
				return False

		if proc.call("/sbin/service mqbroker restart") != 0:
			return False

		self.send_nagios_commands('disable_all_notifications',
			'stop_executing_host_checks', 'stop_executing_service_checks',
			'stop_using_event_handlers')
		return True

	def become_active(self):
		vifcmd = "/sbin/ip addr add {0} dev {1}".format(active_vifip, active_vifif)
		if proc.call(vifcmd) != 0:
			return False

		if proc.call("/sbin/service nagios status") == 1:
			if proc.call("/sbin/service nagios start") != 0:
				return False

		if proc.call("/sbin/service mqbroker restart") != 0:
			return False

		self.send_nagios_commands('enable_all_notifications',
			'start_executing_host_checks', 'start_executing_service_checks',
			'start_using_event_handlers')
		return True

run = haagent(master_eventsa, master_statea, local_eventsa, local_cmda, local_statea)

#while True:
#	run.passive_loop(timeout)
#	run.active_loop(timeout)
