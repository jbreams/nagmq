#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <signal.h>
#define NSCORE 1
#include "naginclude/nebstructs.h"
#include "naginclude/nebcallbacks.h"
#include "naginclude/nebmodules.h"
#include "naginclude/nebmods.h"
#include "naginclude/nagios.h"
#include "naginclude/objects.h"
#include "naginclude/broker.h"
#include "naginclude/comments.h"
#include "naginclude/downtime.h"
#include <zmq.h>
#include <pthread.h>
#include "jansson.h"
#include "common.h"

extern int errno;

static void process_bulkstate(json_t * payload) {
	size_t max, i;
	json_t * statedata;

	statedata = json_object_get(payload, "data");
	if(!statedata || !json_is_array(statedata)) {
		json_decref(payload);
		return;
	}

	max = json_array_size(statedata);

	for(i = 0; i < max; i++) {
		char * service_description = NULL, * host_name, *type;
		char * plugin_output, * long_output = NULL, *perf_data = NULL;
		int state, current_attempt, acknowledged, state_type;
		int is_flapping, notifications_enabled, checks_enabled;
		int passive_checks_enabled = -1, event_handler_enabled;
		int flap_detection_enabled, has_been_checked;
		time_t last_check, last_state_change, last_notification;
		json_t *jlong_output = NULL, *jperf_data = NULL;
		double latency, execution_time;

		json_t * el = json_array_get(statedata, i);
		if(json_unpack(el, 
			"{s:s s?:s s:s s?:o s?:o s:i s:i s:i s:b "
			"s:b s:b s:b s:b s:b s?:b s?:b s:s s:i s:b s:i "
			"s:f s:f s:i }",
			"host_name", &host_name,
			"service_description", &service_description,
			"plugin_output", &plugin_output,
			"long_output", &jlong_output,
			"perf_data", &perf_data,
			"current_state", &state,
			"current_attempt", &current_attempt,
			"state_type", &state_type,
			"is_flapping", &is_flapping,
			"notifications_enabled", &notifications_enabled,
			"checks_enabled", &checks_enabled,
			"event_handler_enabled", &event_handler_enabled,
			"flap_detection_enabled", &flap_detection_enabled,
			"problem_has_been_acknowledged", &acknowledged,
			"accept_passive_service_checks", &passive_checks_enabled,
			"accept_passive_host_checks", &passive_checks_enabled,
			"type", &type,
			"last_check", &last_check,
			"has_been_checked", &has_been_checked,
			"last_state_change", &last_state_change,
			"latency", &latency,
			"execution_time", &execution_time,
			"last_notification", &last_notification) < 0)
			continue;

		if(passive_checks_enabled < 0)
			continue;

		if(strcmp(type, "host") != 0 && strcmp(type, "service") != 0)
			continue;

		if(jlong_output && json_is_string(jlong_output))
			long_output = json_string_value(jlong_output);
		if(jperf_data && json_is_string(jperf_data))
			perf_data = json_string_value(jperf_data);

		if(service_description) {
			service * svctarget = find_service(host_name, service_description);
			if(!svctarget)
				continue;
			svctarget->current_state = state;
			svctarget->current_attempt = current_attempt;
			svctarget->state_type = state_type;
			svctarget->is_flapping = is_flapping;
			svctarget->notifications_enabled = notifications_enabled;
			svctarget->checks_enabled = checks_enabled;
			svctarget->event_handler_enabled = event_handler_enabled;
			svctarget->flap_detection_enabled = flap_detection_enabled;
			svctarget->problem_has_been_acknowledged = acknowledged;
			svctarget->accept_passive_service_checks = passive_checks_enabled;
			if(svctarget->plugin_output)
				free(svctarget->plugin_output);
			svctarget->plugin_output = strdup(plugin_output);
			if(svctarget->long_plugin_output)
				free(svctarget->long_plugin_output);
			svctarget->long_plugin_output = long_output ? strdup(long_output) : NULL;
			if(svctarget->perf_data)
				free(svctarget->perf_data);
			svctarget->perf_data = perf_data ? strdup(perf_data) : NULL;
			svctarget->last_check = last_check;
			svctarget->last_state_change = last_state_change;
			svctarget->has_been_checked = has_been_checked;
			svctarget->last_notification = last_notification;
			svctarget->latency = latency;
			svctarget->execution_time = execution_time;
		}			
		else {
			host * hsttarget = find_host(host_name);
			if(!hsttarget)
				continue;
			hsttarget->current_state = state;
			hsttarget->current_attempt = current_attempt;
			hsttarget->state_type = state_type;
			hsttarget->is_flapping = is_flapping;
			hsttarget->notifications_enabled = notifications_enabled;
			hsttarget->checks_enabled = checks_enabled;
			hsttarget->event_handler_enabled = event_handler_enabled;
			hsttarget->flap_detection_enabled = flap_detection_enabled;
			hsttarget->problem_has_been_acknowledged = acknowledged;
			hsttarget->accept_passive_host_checks = passive_checks_enabled;
			if(hsttarget->plugin_output)
				free(hsttarget->plugin_output);
			hsttarget->plugin_output = strdup(plugin_output);
			if(hsttarget->long_plugin_output)
				free(hsttarget->long_plugin_output);
			hsttarget->long_plugin_output = long_output ? strdup(long_output) : NULL;
			if(hsttarget->perf_data)
				free(hsttarget->perf_data);
			hsttarget->perf_data = perf_data ? strdup(perf_data) : NULL;
			hsttarget->last_check = last_check;
			hsttarget->last_state_change = last_state_change;
			hsttarget->has_been_checked = has_been_checked;
			hsttarget->last_host_notification = last_notification;
			hsttarget->latency = latency;
			hsttarget->execution_time = execution_time;
		}
	}

	json_decref(payload);
}

static void process_status(json_t * payload) {
	char * host_name, *service_description = NULL, *output = NULL;
	check_result * newcr = NULL, t;
	struct timeval start, finish;

	init_check_result(&t);
	t.output_file = NULL;
	t.output_file_fp = NULL;
	memset(&start, 0, sizeof(struct timeval));
	memset(&finish, 0, sizeof(struct timeval));
	if(json_unpack(payload, "{s:s s:s s?:s s:i s?:{s:i s?:i} s:{s:i s?:i}"
		"s:i s?:i s?:i s?:i, s?:f, s?:i s?:i *}",
		"host_name", &host_name, "output", &output, "service_description",
		&service_description, "return_code", &t.return_code, "start_time",
		"tv_sec", &start.tv_sec, "tv_usec", &start.tv_usec, "finish_time", 
		"tv_sec", &finish.tv_sec, "tv_usec", &finish.tv_usec, "check_type",
		&t.check_type, "check_options", &t.check_options, "scheduled_check",
		&t.scheduled_check, "reschedule_check", &t.reschedule_check,
		"latency", &t.latency, "early_timeout", &t.early_timeout,
		"exited_ok", &t.exited_ok) != 0) {
		json_decref(payload);
		return;
	}

	service * service_target = NULL;
	if(service_description)
		service_target = find_service(host_name, service_description);
	host * host_target = find_host(host_name);
	if(host_target == NULL || (service_description && !service_target)) {
		json_decref(payload);
		return;
	}

	newcr = malloc(sizeof(check_result));
	memcpy(newcr, &t, sizeof(check_result));
	memcpy(&newcr->start_time, &start, sizeof(struct timeval));
	memcpy(&newcr->finish_time, &finish, sizeof(struct timeval));
	newcr->host_name = strdup(host_name);
	if(service_target) {
		newcr->service_description = strdup(service_description);
		newcr->object_check_type = SERVICE_CHECK;
	}
	newcr->output = strdup(output);
	json_decref(payload);

	add_check_result_to_list(newcr);
}

static void process_acknowledgement(json_t * payload) {
	char *host_name, *service_description = NULL,
		*author_name, *comment_data;
	int persistent_comment = 0, notify_contacts = 0,
		acknowledgement_type = 0;
	host * host_target = NULL;
	service * service_target = NULL;
	json_error_t err;
	if(json_unpack_ex(payload, &err, 0, "{s:s s?:s s:s s:s s?:i s?:b s?:b}",
		"host_name", &host_name, "service_description", &service_description,
		"author_name", &author_name, "comment_data", &comment_data,
		"acknowledgement_type", &acknowledgement_type, "notify_contacts",
		&notify_contacts, "persistent_comment", &persistent_comment) != 0) {
		json_decref(payload);
		return;
	}

	host_target = find_host(host_name);
	if(service_description)
		service_target = find_service(host_name, service_description);

	if(service_target)
		acknowledge_service_problem(service_target, author_name, comment_data,
			acknowledgement_type, notify_contacts, persistent_comment);
	else if(host_target)
		acknowledge_host_problem(host_target, author_name, comment_data,
			acknowledgement_type, notify_contacts, persistent_comment);
	json_decref(payload);
}

static void process_comment(json_t * payload) {
	char * host_name, *service_description = NULL, *comment_data, *author_name;
	time_t entry_time = 0, expire_time = 0;
	int persistent = 0, expires = 0;
	if(json_unpack(payload, "{s:s s?:s s:s s:{s:i} s:b s:b s:i s:s}",
		"host_name", &host_name, "service_description", &service_description,
		"comment_data", &comment_data, "timestamp", "tv_sec", &entry_time,
		"persistent", &persistent, "expires", &expires, "expire_time",
		&expire_time, "author_name", &author_name) != 0) {
		json_decref(payload);
		return;
	}

	add_new_comment((service_description==NULL) ? HOST_COMMENT:SERVICE_COMMENT,
		USER_COMMENT, host_name, service_description, entry_time, author_name,
		comment_data, persistent, COMMENTSOURCE_EXTERNAL, expires, expire_time,
		NULL);
	json_decref(payload);
}

static void process_downtime(json_t * payload) {
	char * host_name, * service_description = NULL;
	char * author_name, *comment_data;
	time_t start_time = 0, end_time = 0, entry_time = 0;
	int fixed;
	unsigned long duration = 0, triggered_by = 0, downtimeid;

	if(json_unpack(payload, "{s:s s?:s s:i s:s s:s s:i s:i s:b s:i s:i}",
		"host_name", &host_name, "service_description", &service_description,
		"entry_time", &entry_time, "author_name", &author_name, "comment_data",
		&comment_data, "start_time", &start_time, "end_time", &end_time,
		"fixed", &fixed, "duration", &duration, "triggered_by",
		&triggered_by) != 0) {
		json_decref(payload);
		return;
	}

	schedule_downtime(service_description != NULL ? SERVICE_DOWNTIME:
		HOST_DOWNTIME, host_name, service_description, entry_time,
		author_name, comment_data, start_time, end_time, fixed,
		triggered_by, duration, &downtimeid);
	json_decref(payload);
}

static void process_cmd(json_t * payload) {
	host * host_target = NULL;
	service * service_target = NULL;
	char * host_name = NULL, *service_description = NULL, *cmd_name;
	char * comment = NULL;
	time_t start_time = 0;

	if(json_unpack(payload, "{s?:s s:?s s:s s?:s s?:i}",
		"host_name", &host_name, "service_description", &service_description,
		"command_name", &cmd_name, "comment", &comment, "start_time",
		&start_time) != 0) {
		json_decref(payload);
		return;
	}

	if(host_name)
		host_target = find_host(host_name);
	if(host_target && service_description)
		service_target = find_service(host_name, service_description);

	if(strcmp(cmd_name, "disable_service_checks") == 0 && service_target)
		disable_service_checks(service_target);
	else if(strcmp(cmd_name, "enable_service_checks") == 0 && service_target)
		enable_service_checks(service_target);
	else if(strcmp(cmd_name, "enable_all_notifications") == 0)
		enable_all_notifications();
	else if(strcmp(cmd_name, "disable_all_notification") == 0)
		disable_all_notifications();
	else if(strcmp(cmd_name, "enable_service_notifications") == 0 && service_target)
		enable_service_notifications(service_target);
	else if(strcmp(cmd_name, "disable_service_notifications") == 0 && service_target)
		disable_service_notifications(service_target);
	else if(strcmp(cmd_name, "enable_host_notifications") == 0 && host_target)
		enable_host_notifications(host_target);
	else if(strcmp(cmd_name, "disable_host_notifications") == 0 && host_target)
		disable_host_notifications(host_target);
	else if(strcmp(cmd_name, "remove_host_acknowledgement") == 0 && host_target)
		remove_host_acknowledgement(host_target);
	else if(strcmp(cmd_name, "remove_service_acknowledgement") == 0 && service_target)
		remove_service_acknowledgement(service_target);
	else if(strcmp(cmd_name, "start_executing_service_checks") == 0)
		start_executing_service_checks();
	else if(strcmp(cmd_name, "stop_executing_service_checks") == 0)
		stop_executing_service_checks();
	else if(strcmp(cmd_name, "start_accepting_passive_service_checks") == 0)
		start_accepting_passive_service_checks();
	else if(strcmp(cmd_name, "stop_accepting_passive_service_checks") == 0)
		stop_accepting_passive_service_checks();
	else if(strcmp(cmd_name, "enable_passive_service_checks") == 0 && service_target)
		enable_passive_service_checks(service_target);
	else if(strcmp(cmd_name, "disable_passive_service_checks") == 0 && service_target)
		disable_passive_service_checks(service_target);
	else if(strcmp(cmd_name, "start_using_event_handlers") == 0)
		start_using_event_handlers();
	else if(strcmp(cmd_name, "stop_using_event_handlers") == 0)
		stop_using_event_handlers();
	else if(strcmp(cmd_name, "enable_service_event_handler") == 0 && service_target)
		enable_service_event_handler(service_target);
	else if(strcmp(cmd_name, "disable_service_event_handler") == 0 && service_target)
		disable_service_event_handler(service_target);
	else if(strcmp(cmd_name, "enable_host_event_handler") == 0 && host_target)
		enable_host_event_handler(host_target);
	else if(strcmp(cmd_name, "disable_host_event_handler") == 0 && host_target)
		disable_host_event_handler(host_target);
	else if(strcmp(cmd_name, "enable_host_checks") == 0 && host_target)
		enable_host_checks(host_target);
	else if(strcmp(cmd_name, "disable_host_checks") == 0 && host_target)
		disable_host_checks(host_target);
	else if(strcmp(cmd_name, "enable_service_freshness_checks") == 0)
		enable_service_freshness_checks();
	else if(strcmp(cmd_name, "start_obsessing_over_service") == 0 && service_target)
		start_obsessing_over_service(service_target);
	else if(strcmp(cmd_name, "stop_obsessing_over_service") == 0 && service_target)
		stop_obsessing_over_service(service_target);
	else if(strcmp(cmd_name, "start_obsessing_over_host") == 0 && host_target)
		start_obsessing_over_host(host_target);
	else if(strcmp(cmd_name, "stop_obsessing_over_host") == 0 && host_target)
		stop_obsessing_over_host(host_target);
	else if(strcmp(cmd_name, "enable_performance_data") == 0)
		enable_performance_data();
	else if(strcmp(cmd_name, "disable_performance_data") == 0)
		disable_performance_data();
	else if(strcmp(cmd_name, "start_executing_host_checks") == 0)
		start_executing_host_checks();
	else if(strcmp(cmd_name, "stop_executing_host_checks") == 0)
		stop_executing_host_checks();
	else if(strcmp(cmd_name, "start_accepting_passive_host_checks") == 0)
		start_accepting_passive_host_checks();
	else if(strcmp(cmd_name, "stop_accepting_passive_host_checks") == 0)
		stop_accepting_passive_host_checks();
	else if(strcmp(cmd_name, "enable_passive_host_checks") == 0 && host_target)
		enable_passive_host_checks(host_target);
	else if(strcmp(cmd_name, "disable_passive_host_checks") == 0 && host_target)
		disable_passive_host_checks(host_target);
	else if(strcmp(cmd_name, "enable_host_flap_detection") == 0 && host_target)
		enable_host_flap_detection(host_target);
	else if(strcmp(cmd_name, "disable_host_flap_detection") == 0 && host_target)
		disable_host_flap_detection(host_target);
	else if(strcmp(cmd_name, "enable_service_flap_detection") == 0 && service_target)
		enable_service_flap_detection(service_target);
	else if(strcmp(cmd_name, "disable_service_flap_detection") == 0 && service_target)
		disable_service_flap_detection(service_target);
	else if((strcmp(cmd_name, "schedule_host_check") == 0 && host_target) ||
		(strcmp(cmd_name, "schedule_service_check") == 0&& service_target)) {
		time_t next_check;
		int force_execution = 0, freshness_check = 0, orphan_check = 0;
		if(json_unpack(payload, "{ s:i s?:b s?:b s:?b }",
			"next_check", &next_check, "force_execution", &force_execution,
			"freshness_check", &freshness_check, "orphan_check",
			&orphan_check) != 0) {
			json_decref(payload);
			return;
		}
		int flags = CHECK_OPTION_NONE;
		if(force_execution)
			flags |= CHECK_OPTION_FORCE_EXECUTION;
		if(freshness_check)
			flags |= CHECK_OPTION_FRESHNESS_CHECK;
		if(orphan_check)
			flags |= CHECK_OPTION_ORPHAN_CHECK;
		if(service_target)
			schedule_service_check(service_target, next_check, flags);
		else
			schedule_host_check(host_target, next_check, flags);
	}
	else if((strcmp(cmd_name, "disable_and_propagate_notifications") == 0||
		strcmp(cmd_name, "enable_and_propagate_notifications") == 0) &&
		host_target) {
		int affect_top_host = 0, affect_hosts = 0, affect_services = 0,
			level = 0;
		if(json_unpack(payload, "{ s?:b s?:b s?:b s?:i }",
			"affect_top_host", &affect_top_host, "affect_hosts",
			&affect_hosts, "affect_services", &affect_services,
			"level", &level) != 0) {
			json_decref(payload);
			return;
		}
		if(strcmp(cmd_name, "disable_and_propagate_notifications") == 0)
			disable_and_propagate_notifications(host_target, level,
				affect_top_host, affect_hosts, affect_services);
		else if(strcmp(cmd_name, "enable_and_propagate_notifications") == 0)
			enable_and_propagate_notifications(host_target, level,
				affect_top_host, affect_hosts, affect_services);
	}
	else if(strcmp(cmd_name, "delete_downtime") == 0)
		delete_downtime_by_hostname_service_description_start_time_comment(
			host_name, service_description, start_time, comment);

	json_decref(payload);
}

void process_pull_msg(zmq_msg_t * payload_msg) {
	char * type = NULL;

	json_t * payload = json_loadb(zmq_msg_data(payload_msg),
		zmq_msg_size(payload_msg), 0, NULL);
	if(payload == NULL)
		return;		
	
	if(json_unpack(payload, "{ s:s }", "type", &type) != 0) {
		json_decref(payload);
		return;
	}
	size_t typelen = strlen(type);

	if(strncmp(type, "command", typelen) == 0)
		process_cmd(payload);
	else if(strncmp(type, "host_check_processed", typelen) == 0 ||
		strncmp(type, "service_check_processed", typelen) == 0)
		process_status(payload);
	else if(strncmp(type, "acknowledgement", typelen) == 0)
		process_acknowledgement(payload);
	else if(strncmp(type, "comment_add", typelen) == 0)
		process_comment(payload);
	else if(strncmp(type, "downtime_add", typelen) == 0)
		process_downtime(payload);
	else if(strncmp(type, "state_data", typelen) == 0)
		process_bulkstate(payload);
	return;
}
