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
	char * host_name = (char*)json_string_value(
		json_object_get(payload, "host_name"));
	char * service_description = (char*)json_string_value(
		json_object_get(payload, "service_description"));
	if(!host_name ||
		!json_is_integer(json_object_get(payload, "return_code")) ||
		!json_is_string(json_object_get(payload, "output"))) {
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

	char * output = (char*)json_string_value(
		json_object_get(payload, "output"));
	if(output == NULL) {
		json_decref(payload);
		return;
	}
	int retcode = json_integer_value(
		json_object_get(payload, "return_code"));
	
	json_t * endtimetvsec = (json_object_get(
		json_object_get(payload, "end_time"), "tv_sec"));
	if(!endtimetvsec || !json_is_integer(endtimetvsec)) {
		json_decref(payload);
		return;
	}

	time_t timestamp = json_integer_value(endtimetvsec);
	if(service_target)
		process_passive_service_check(timestamp, host_name,
			service_description, retcode, output);
	else
		process_passive_host_check(timestamp, host_name,
			retcode, output);

	json_decref(payload);
}

static void process_acknowledgement(json_t * payload) {
	host * host_target;
	service * service_target;

	char * service_description = (char*)json_string_value(
		json_object_get(payload, "service_description"));
	char * host_name = (char*)json_string_value(
		json_object_get(payload, "host_name"));

	if(host_name)
		host_target = find_host(host_name);
	if(host_target && service_description)
		service_target = find_service(host_name, service_description);

	if(!json_is_string(json_object_get(payload, "author_name"))||
		!json_is_string(json_object_get(payload, "comment_data"))||
		!json_is_integer(json_object_get(payload, "acknowledgement_type"))) {
		json_decref(payload);
		return;
	}
	char * author = (char*)json_string_value(
		json_object_get(payload, "author_name"));
	char * ackdata = (char*)json_string_value(
		json_object_get(payload, "comment_data"));
	int persistent = json_is_true(
		json_object_get(payload, "persistent_comment"));
	int notify = json_is_true(
		json_object_get(payload, "notify_comments"));
	int type = json_integer_value(
		json_object_get(payload, "acknowledgement_type"));
	if(service_target)
		acknowledge_service_problem(service_target, author, ackdata,
			type, notify, persistent);
	else 
		acknowledge_host_problem(host_target, author, ackdata,
			type, notify, persistent);
	json_decref(payload);
}

static void process_cmd(json_t * payload) {
	host * host_target;
	service * service_target;
	char * cmd_name = (char*)json_string_value(
		json_object_get(payload, "command_name"));
	if(!cmd_name) {
		json_decref(payload);
		return;
	}
	char * service_description = (char*)json_string_value(
		json_object_get(payload, "service_description"));
	char * host_name = (char*)json_string_value(
		json_object_get(payload, "host_name"));

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
		json_t * schedatobj = json_object_get(payload, "next_check");
		if(schedatobj == NULL || !json_is_integer(schedatobj)) {
			json_decref(payload);
			return;
		}
		time_t schedat = json_integer_value(schedatobj);
		int flags = CHECK_OPTION_NONE;
		if(json_is_true(json_object_get(payload, "force_execution")))
			flags |= CHECK_OPTION_FORCE_EXECUTION;
		if(json_is_true(json_object_get(payload, "freshness_check")))
			flags |= CHECK_OPTION_FRESHNESS_CHECK;
		if(json_is_true(json_object_get(payload, "orphan_check")))
			flags |= CHECK_OPTION_ORPHAN_CHECK;
		if(service_target)
			schedule_service_check(service_target, schedat, flags);
		else
			schedule_host_check(host_target, schedat, flags);
	}
	else if(strcmp(cmd_name, "enable_and_propagate_notifications") == 0 && host_target) {
		int affect_top_hosts = json_is_true(
			json_object_get(payload, "affect_top_host"));
		int affect_hosts = json_is_true(
			json_object_get(payload, "affect_hosts"));
		int affect_services = json_is_true(
			json_object_get(payload, "affect_services"));
		int level = 0;
		if(json_is_integer(json_object_get(payload, "level")))
			level = json_integer_value(json_object_get(payload, "level"));
		enable_and_propagate_notifications(host_target, level,
			affect_top_hosts, affect_hosts, affect_services);
	}
	else if(strcmp(cmd_name, "disable_and_propagate_notifications") == 0 && host_target) {
		int affect_top_hosts = json_is_true(
			json_object_get(payload, "affect_top_host"));
		int affect_hosts = json_is_true(
			json_object_get(payload, "affect_hosts"));
		int affect_services = json_is_true(
			json_object_get(payload, "affect_services"));
		int level = 0;
		if(json_is_integer(json_object_get(payload, "level")))
			level = json_integer_value(json_object_get(payload, "level"));
		disable_and_propagate_notifications(host_target, level,
			affect_top_hosts, affect_hosts, affect_services);
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
	if(setup_zmq((char*)args, ZMQ_SUB, &ctx, &sock) < 0)
		return NULL;
	zmq_setsockopt(sock, ZMQ_SUBSCRIBE, "command", sizeof("command"));
	zmq_setsockopt(sock, ZMQ_SUBSCRIBE, 
		"service_check_processed", sizeof("service_check_processed"));
	zmq_setsockopt(sock, ZMQ_SUBSCRIBE,
		"host_check_processed", sizeof("host_check_processed"));
	zmq_setsockopt(sock, ZMQ_SUBSCRIBE,
		"acknowledgement", sizeof("acknowledgement"));
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
