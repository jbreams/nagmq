#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#define NSCORE 1
#include "naginclude/nebstructs.h"
#include "naginclude/nebcallbacks.h"
#include "naginclude/nebmodules.h"
#include "naginclude/nebmods.h"
#include "naginclude/nagios.h"
#include "naginclude/objects.h"
#include "naginclude/broker.h"
#include "naginclude/comments.h"
#include <zmq.h>
#include <pthread.h>
#include "jansson.h"

NEB_API_VERSION(CURRENT_NEB_API_VERSION)
static void * nagmq_handle = NULL;
static void * ctx;
static char * args;
static pthread_t threadid;
static pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t recv_loop_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int errno;

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	if(args)
		free(args);

	return 0;
}

int setup_zmq(char * args, int type, 
	void ** ctxo, void ** socko);

static void process_status(json_t * payload) {
	char * host_name, *service_description = NULL, *output;
	int return_code;
	time_t timestamp;

	if(json_unpack(payload, "{s:s s:s s?:s s:i s:{s:i}}",
		"host_name", &host_name, "output", &output,
		"service_description", &service_description,
		"return_code", &return_code, "end_time", "tv_sec",
		&timestamp) != 0) {
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

	if(service_target)
		process_passive_service_check(timestamp, host_name,
			service_description, return_code, output);
	else
		process_passive_host_check(timestamp, host_name,
			return_code, output);

	json_decref(payload);
}

static void process_acknowledgement(json_t * payload) {
	char *host_name, *service_description = NULL,
		*author_name, *comment_data;
	int persistent_comment = 0, notify_contacts = 0,
		acknowledgement_type = 0;
	host * host_target;
	service * service_target;

	if(json_unpack(payload, "{s:s s?:s s:s s:s s?:i s?:b s?:b s?:b}",
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
	json_decret(payload);
}

static void process_cmd(json_t * payload) {
	host * host_target;
	service * service_target;
	char * host_name, *service_description = NULL, *cmd_name;

	if(json_unpack(payload, "{s:s s:?s s:s}",
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
	else if(strcmp(cmd_name, "start_executing_service_checks"))
		start_executing_service_checks();
	else if(strcmp(cmd_name, "stop_executing_service_checks"))
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
	else if(strcmp(cmd_name, "remove_host_acknowledgement") == 0 && host_target)
		remove_host_acknowledgement(host_target);
	else if(strcmp(cmd_name, "remove_service_acknowledgement") == 0 && service_target)
		remove_service_acknowledgement(service_target);

	json_decref(payload);
}

void * recv_loop(void * parg) {
	void * sock;
	zmq_msg_t type_msg;

	pthread_mutex_lock(&recv_loop_mutex);
	if(setup_zmq((char*)args, ZMQ_PULL, &ctx, &sock) < 0)
		return NULL;
	pthread_mutex_signal(&init_cond);
	pthread_mutex_unlock(&recv_loop_mutex);

	zmq_msg_init(&type_msg);
	while(zmq_recv(sock, &type_msg, 0) == 0) {
		zmq_msg_t payload_msg;
		int ismore; 
		size_t imlen = sizeof(ismore);
		zmq_getsockopt(sock, ZMQ_RCVMORE, &ismore, &imlen);
		if(!ismore) {
			zmq_msg_close(&type_msg);
			continue;
		}

		zmq_msg_init(&payload_msg);
		if(zmq_recv(sock, &payload_msg, 0) != 0) {
			zmq_msg_close(&payload_msg);
			zmq_msg_close(&type_msg);
			zmq_msg_init(&type_msg);
			continue;
		}

		json_t * payload = json_loadb(zmq_msg_data(&payload_msg),
			zmq_msg_size(&payload_msg), 0, NULL);
		zmq_msg_close(&payload_msg);
		if(payload == NULL) {
			zmq_msg_close(&type_msg);
			zmq_msg_init(&type_msg);
			continue;		
		}
		
		char * type = zmq_msg_data(&type_msg);
		size_t typelen = zmq_msg_size(&type_msg);
		if(strncmp(type, "command", typelen) == 0)
			process_cmd(payload);
		else if(strncmp(type, "host_check_processed", typelen) == 0)
			process_status(payload);
		else if(strncmp(type, "service_check_processed", typelen) == 0)
			process_status(payload);
		else if(strncmp(type, "acknowledgement", typelen) == 0)
			process_acknowledgement(payload);
		else if(strncmp(type, "comment_add", typelen) == 0)
			process_comment(payload);
		zmq_msg_close(&type_msg);
		zmq_msg_init(&type_msg);
	}

	return NULL;	
}

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	if(ps->type == NEBTYPE_PROCESS_EVENTLOOPEND) {
		zmq_term(ctx);
		pthread_join(threadid, NULL);
		return 0;
	}
	else if(ps->type != NEBTYPE_PROCESS_EVENTLOOPSTART)
		return 0;

	pthread_mutex_lock(&recv_loop_mutex);
	if(pthread_create(&threadid, NULL, recv_loop, NULL) < 0) {
		syslog(LOG_ERR, "Error creating ZMQ recv loop: %m");
		return -1;
	}
	pthread_cond_wait(&init_cond, &recv_loop_mutex);
	pthread_detach(threadid);

	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * handle) {
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq subscriber");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "0.8");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Subscribes to Nagios data on 0MQ");

	neb_register_callback(NEBCALLBACK_PROCESS_DATA, handle,
		0, handle_startup);

	nagmq_handle = handle;
	args = strdup(localargs);

	return 0;
}
