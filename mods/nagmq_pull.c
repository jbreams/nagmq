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

extern int errno;

static check_result * crhead = NULL;
pthread_mutex_t cr_mutex = PTHREAD_MUTEX_INITIALIZER;
void * crpullsock = NULL;

int handle_timedevent(int which, void * obj) {
	nebstruct_timed_event_data * data = obj;
	if(which != NEBCALLBACK_TIMED_EVENT_DATA)
		return ERROR;
	if(data->type != NEBTYPE_TIMEDEVENT_EXECUTE &&
		data->event_type != EVENT_CHECK_REAPER)
		return 0;

	int rc;
	if(crpullsock) {
		while(1) {
			zmq_msg_t crm;
			zmq_msg_init(&crm);
			if(zmq_recv(crpullsock, &crm, ZMQ_NOBLOCK) != 0) {
				if(errno != EINTR)
					break;
			}

			check_result * cr = zmq_msg_data(&crm);
			zmq_msg_close(&crm);
			add_check_result_to_list(cr);
		}
	} else {
		pthread_mutex_lock(&cr_mutex);
		check_result *crsave = crhead;
		crhead = NULL;
		pthread_mutex_unlock(&cr_mutex);
		while(crsave) {
			check_result *tmp = crsave->next;
			crsave->next = NULL;
			add_check_result_to_list(crsave);
			crsave = tmp;
		}
	}

	return 0;
}

static void process_status(json_t * payload, void * ressock) {
	char * host_name, *service_description = NULL, *output = NULL;
	check_result * newcr = NULL, t;
	struct timeval start, finish;
	time_t timestamp;

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

	if(ressock) {
		zmq_msg_t rmsg;
		zmq_msg_init_data(&rmsg, newcr, sizeof(check_result), NULL, NULL);
		zmq_send(ressock, &rmsg, 0);
		zmq_msg_close(&rmsg);
	} else {
		pthread_mutex_lock(&cr_mutex);
		newcr->next = crhead;
		crhead = newcr;
		pthread_mutex_unlock(&cr_mutex);
	}
}

static void process_acknowledgement(json_t * payload) {
	char *host_name, *service_description = NULL,
		*author_name, *comment_data;
	int persistent_comment = 0, notify_contacts = 0,
		acknowledgement_type = 0;
	host * host_target;
	service * service_target;
	json_error_t err;
	if(json_unpack_ex(payload, &err, 0, "{s:s s?:s s:s s:s s?:i s?:b s?:b s?:b}",
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
	else 
		acknowledge_host_problem(host_target, author_name, comment_data,
			acknowledgement_type, notify_contacts, persistent_comment);
	json_decref(payload);
}

static void process_comment(json_t * payload) {
	char * host_name, *service_description = NULL, *comment_data, *author_name;
	time_t entry_time, expire_time;
	int persistent = 0, expires = 0;
	if(json_unpack(payload, "{s:s s?:s s:s s:{s:i} s:b s:b s:i}",
		"host_name", &host_name, "service_description", &service_description,
		"comment_data", &comment_data, "timestamp", "tv_sec", &entry_time,
		"persistent", &persistent, "expires", &expires, "expire_time",
		&expire_time) != 0) {
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
	time_t start_time, end_time, entry_time;
	int fixed;
	unsigned long duration, triggered_by, downtimeid;

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
	host * host_target;
	service * service_target;
	char * host_name = NULL, *service_description = NULL, *cmd_name;

	if(json_unpack(payload, "{s?:s s:?s s:s}",
		"host_name", &host_name, "service_description", &service_description,
		"command_name", &cmd_name) != 0) {
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

	json_decref(payload);
}

void process_pull_msg(zmq_msg_t * payload_msg, void * outsock) {
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
		process_status(payload, outsock);
	else if(strncmp(type, "acknowledgement", typelen) == 0)
		process_acknowledgement(payload);
	else if(strncmp(type, "comment_add", typelen) == 0)
		process_comment(payload);
	else if(strncmp(type, "downtime_add", typelen) == 0)
		process_downtime(payload);
	return;
}

extern void * zmq_ctx;
void * pull_thread(void * arg) {
	int rc;
	sigset_t signal_set;
	sigfillset(&signal_set);
	pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
	void * intsock = zmq_socket(zmq_ctx, ZMQ_PULL);
	if(intsock == NULL)
		return NULL;
	zmq_connect(intsock, "inproc://nagmq_pull_bus");

	void * intresult = zmq_socket(zmq_ctx, ZMQ_PUSH);
	if(intresult == NULL)
		return NULL;
	zmq_connect(intresult, "inproc://nagmq_cr_bus");

	while(1) {
		zmq_msg_t payload;
		zmq_msg_init(&payload);
		
		if((rc = zmq_recv(intsock, &payload, 0)) != 0) {
			rc = errno;
			if(rc == ETERM)
				break;
			else if(rc == EINTR)
				continue;
			else
				syslog(LOG_ERR, "Error receiving for pull events! %s", zmq_strerror(rc));
				break;
		}

		process_pull_msg(&payload, intresult);
		zmq_msg_close(&payload);
	}

	zmq_close(intresult);
	zmq_close(intsock);
}
