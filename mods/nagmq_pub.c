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
#include "json.h"

static void * nagmq_handle = NULL;
static void * zmq_ctx = NULL;
static void * pubext = NULL;
extern int errno;
static char * args = NULL;

NEB_API_VERSION(CURRENT_NEB_API_VERSION)

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	if(args)
		free(args);

	return 0;
}

static struct payload * parse_program_status(nebstruct_program_status_data * state) {
	struct payload * ret = payload_new();	

	payload_new_string(ret, "type", "program_status");
	payload_new_integer(ret, "program_start", state->program_start);
	payload_new_integer(ret, "pid", state->pid);
	payload_new_integer(ret, "daemon_mode", state->daemon_mode);
	payload_new_integer(ret, "last_command_check", state->last_command_check);
	payload_new_integer(ret, "last_log_rotation", state->last_log_rotation);
	payload_new_integer(ret, "notifications_enabled", state->notifications_enabled);
	payload_new_integer(ret, "active_service_checks_enabled", state->active_service_checks_enabled);
	payload_new_integer(ret, "passive_service_checks_enabled", state->passive_service_checks_enabled);
	payload_new_integer(ret, "active_host_checks_enabled", state->active_host_checks_enabled);
	payload_new_integer(ret, "passive_host_checks_enabled", state->passive_host_checks_enabled);
	payload_new_integer(ret, "event_handlers_enabled", state->event_handlers_enabled);
	payload_new_integer(ret, "flap_detection_enabled", state->flap_detection_enabled);
	payload_new_integer(ret, "failure_prediction_enabled", state->failure_prediction_enabled);
	payload_new_integer(ret, "process_performance_data", state->process_performance_data);
	payload_new_integer(ret, "obsess_over_hosts", state->obsess_over_hosts);
	payload_new_integer(ret, "obsess_over_services", state->obsess_over_services);
	return ret;
}

static struct payload * parse_host_check(nebstruct_host_check_data * state) {
	struct payload * ret = payload_new();
	host * obj = find_host(state->host_name);

	payload_new_string(ret, "host_name", state->host_name);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_integer(ret, "state", state->state);
	payload_new_integer(ret, "last_state", obj->last_state);
	payload_new_integer(ret, "last_hard_state", obj->last_hard_state);
	payload_new_integer(ret, "last_check", obj->last_check);
	payload_new_integer(ret, "last_state_change", obj->last_state_change);

	if(state->type == NEBTYPE_HOSTCHECK_INITIATE) {
		payload_new_string(ret, "type", "host_check_initiate");
		payload_new_string(ret, "command_name", state->command_name);
		payload_new_string(ret, "command_args", state->command_args);
		payload_new_string(ret, "command_line", state->command_line);
		payload_new_integer(ret, "has_been_checked", obj->has_been_checked);
		payload_new_integer(ret, "check_interval", obj->check_interval);
		payload_new_integer(ret, "retry_interval", obj->retry_interval);
		payload_new_integer(ret, "accept_passive_checks", obj->accept_passive_host_checks);
	} else if(state->type == NEBTYPE_HOSTCHECK_PROCESSED) {
		payload_new_string(ret, "type", "host_check_processed");
		payload_new_integer(ret, "timeout", state->timeout);
		payload_new_timestamp(ret, "start_time", &state->start_time);
		payload_new_timestamp(ret, "end_time", &state->end_time);
		payload_new_integer(ret, "early_timeout", state->early_timeout);
		payload_new_double(ret, "execution_time", state->execution_time);
		payload_new_double(ret, "latency", state->latency);
		payload_new_integer(ret, "return_code", state->return_code);
		payload_new_string(ret, "output", state->output);
		payload_new_string(ret, "long_output", state->long_output);
		payload_new_string(ret, "perf_data", state->perf_data);
	}
	return ret;
}

static struct payload * parse_service_check(nebstruct_service_check_data * state) {
	struct payload * ret = payload_new();
	service * obj = find_service(state->host_name, state->service_description);

	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_integer(ret, "state", state->state);
	payload_new_integer(ret, "last_state", obj->last_state);
	payload_new_integer(ret, "last_hard_state", obj->last_hard_state);
	payload_new_integer(ret, "last_check", obj->last_check);
	payload_new_integer(ret, "last_state_change", obj->last_state_change);

	if(state->type == NEBTYPE_SERVICECHECK_INITIATE) {
		payload_new_string(ret, "type", "service_check_initiate");
		payload_new_string(ret, "command_name", state->command_name);
		payload_new_string(ret, "command_args", state->command_args);
		payload_new_string(ret, "command_line", state->command_line);
		payload_new_integer(ret, "has_been_checked", obj->has_been_checked);
		payload_new_integer(ret, "check_interval", obj->check_interval);
		payload_new_integer(ret, "retry_interval", obj->retry_interval);
		payload_new_integer(ret, "accept_passive_checks", obj->accept_passive_service_checks);
	} else if(state->type == NEBTYPE_SERVICECHECK_PROCESSED) {
		payload_new_string(ret, "type", "service_check_processed");
		payload_new_timestamp(ret, "start_time", &state->start_time);
		payload_new_timestamp(ret, "end_time", &state->end_time);
		payload_new_integer(ret, "early_timeout", state->early_timeout);
		payload_new_double(ret, "execution_time", state->execution_time);
		payload_new_double(ret, "latency", state->latency);
		payload_new_integer(ret, "return_code", state->return_code);
		payload_new_string(ret, "output", state->output);
		payload_new_string(ret, "long_output", state->long_output);
		payload_new_string(ret, "perf_data", state->perf_data);
		payload_new_integer(ret, "timeout", state->timeout);
	}
	return ret;
}

static struct payload * parse_acknowledgement(nebstruct_acknowledgement_data * state) {
	struct payload * ret = payload_new();

	payload_new_string(ret, "type", "acknowledgement");
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "state", state->state);
	payload_new_integer(ret, "acknowledgement_type", state->acknowledgement_type);
	payload_new_string(ret, "author_name", state->author_name);
	payload_new_string(ret, "comment_data", state->comment_data);
	payload_new_integer(ret, "is_sticky", state->is_sticky);
	payload_new_integer(ret, "persistent_comment", state->persistent_comment);
	payload_new_integer(ret, "notify_contacts", state->notify_contacts);
	return ret;
}

static struct payload * parse_statechange(nebstruct_statechange_data * state) {
	struct payload * ret = payload_new();

	payload_new_string(ret, "type", "statechange");
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "state", state->state);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_string(ret, "output", state->output);
	return ret;
}

static struct payload * parse_comment(nebstruct_comment_data * state) {
	struct payload * ret = payload_new();

	if(state->type == NEBTYPE_COMMENT_ADD) {
		payload_new_string(ret, "type", "comment_add");
		payload_new_string(ret, "host_name", state->host_name);
		payload_new_string(ret, "service_description", state->service_description);
		payload_new_integer(ret, "entry_time", state->entry_time);
		payload_new_string(ret, "author_name", state->author_name);
		payload_new_string(ret, "comment_data", state->comment_data);
		payload_new_integer(ret, "persistent", state->persistent);
		payload_new_integer(ret, "source", state->source);
		payload_new_integer(ret, "expires", state->expires);
		payload_new_integer(ret, "expire_time", state->expire_time);
	} else if(state->type == NEBTYPE_COMMENT_DELETE) {
		payload_new_string(ret, "type", "comment_delete");
	}

	payload_new_integer(ret, "comment_id", state->comment_id);
	return ret;
}

static struct payload * parse_downtime(nebstruct_downtime_data * state) {
	struct payload * ret = payload_new();

	switch(state->type) {
		case NEBTYPE_DOWNTIME_ADD:
			payload_new_string(ret, "type", "downtime_add");
			break;
		case NEBTYPE_DOWNTIME_DELETE:
			payload_new_string(ret, "type", "downtime_delete");
			payload_new_integer(ret, "downtime_id", state->downtime_id);
			return ret;
		case NEBTYPE_DOWNTIME_START:
			payload_new_string(ret, "type", "downtime_start");
			break;
		case NEBTYPE_DOWNTIME_STOP:
			payload_new_string(ret, "type", "downtime_stop");
			break;
	}

	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "entry_time", state->entry_time);
	payload_new_string(ret, "author_name", state->author_name);
	payload_new_string(ret, "comment_data", state->comment_data);
	payload_new_integer(ret, "start_time", state->start_time);
	payload_new_integer(ret, "end_time", state->end_time);
	payload_new_integer(ret, "fixed", state->fixed);
	payload_new_integer(ret, "duration", state->duration);
	payload_new_integer(ret, "triggered_by", state->triggered_by);
	payload_new_integer(ret, "downtime_id", state->downtime_id);
	return ret;
}

static struct payload * parse_flapping(nebstruct_flapping_data * state) {
	struct payload * ret = payload_new();

	if(state->type == NEBTYPE_FLAPPING_START)
		payload_new_string(ret, "type", "flapping_start");
	else
		payload_new_string(ret, "type", "flapping_stop");
		
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "percent_change", state->percent_change);
	payload_new_double(ret, "high_threshold", state->high_threshold);
	payload_new_double(ret, "low_threshold", state->low_threshold);
	payload_new_integer(ret, "comment_id", state->comment_id);
	return ret;
}

void free_cb(void * ptr, void * hint) {
	free(ptr);
}

static void process_payload(struct payload * payload) {
	zmq_msg_t type, dump;
	int rc;

	zmq_msg_init_data(&type, payload->type, strlen(payload->type),
		free_cb, NULL);
	rc = (zmq_send(pubext, &type, ZMQ_SNDMORE|ZMQ_NOBLOCK) == 0) ? 0 : errno;
	zmq_msg_close(&type);
	if(rc != 0) {
	//	syslog(LOG_ERR, "Error sending type header: %s",
	//		zmq_strerror(rc));
		free(payload->json_buf);
		free(payload->type);
		free(payload);
		return;
	}

	zmq_msg_init_data(&dump, payload->json_buf, payload->bufused, 
		free_cb, NULL);
	if((rc = zmq_send(pubext, &dump, ZMQ_NOBLOCK)) != 0)
		syslog(LOG_ERR, "Error sending payload: %s",
			zmq_strerror(errno));
	zmq_msg_close(&dump);
	free(payload);
}

int handle_nagdata(int which, void * obj) {
	struct payload * payload = NULL;	
	nebstruct_process_data * raw = obj;
	switch(which) {
	case NEBCALLBACK_HOST_CHECK_DATA:
		switch(raw->type) {
			case NEBTYPE_HOSTCHECK_INITIATE:
			case NEBTYPE_HOSTCHECK_PROCESSED:
				payload = parse_host_check(obj);
				break;
			default:
				return 0;
		}
		break;
	case NEBCALLBACK_SERVICE_CHECK_DATA:
		switch(raw->type) {
			case NEBTYPE_SERVICECHECK_INITIATE:
			case NEBTYPE_SERVICECHECK_PROCESSED:
				payload = parse_service_check(obj);
				break;
			default:
				return 0;
		}
		break;
	case NEBCALLBACK_ACKNOWLEDGEMENT_DATA:
		if(raw->type != NEBTYPE_NOTIFICATION_START)
			return 0;
		payload = parse_acknowledgement(obj);
		break;
	case NEBCALLBACK_STATE_CHANGE_DATA:
		payload = parse_statechange(obj);
		break;
	case NEBCALLBACK_COMMENT_DATA:
		if(raw->type == NEBTYPE_COMMENT_LOAD)
			return 0;
		payload = parse_comment(obj);
		break;
	case NEBCALLBACK_DOWNTIME_DATA:
		if(raw->type == NEBTYPE_DOWNTIME_LOAD)
			return 0;
		payload = parse_downtime(obj);
		break;
	case NEBCALLBACK_PROGRAM_STATUS_DATA:
		payload = parse_program_status(obj);
		break;
	case NEBCALLBACK_FLAPPING_DATA:
		payload = parse_flapping(obj);
		break;
	}

	payload_new_timestamp(payload, "timestamp", &raw->timestamp);
	payload_finalize(payload);
	process_payload(payload);
	return 0;
}

int setup_zmq(char * args, int type, 
	void ** ctxo, void ** socko);

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	struct payload * payload;
	if (ps->type == NEBTYPE_PROCESS_EVENTLOOPSTART) {
		if(setup_zmq(args, ZMQ_PUB, &zmq_ctx, &pubext) < 0) {
			nebmodule_deinit(0, 0);
			return -1;
		};

		payload = payload_new();
		payload_new_string(payload, "type", "eventloopstart");
		payload_new_timestamp(payload, "timestamp", &ps->timestamp);
		payload_finalize(payload);
		process_payload(payload);
	} else if(ps->type == NEBTYPE_PROCESS_EVENTLOOPEND) {
		payload = payload_new();
		payload_new_string(payload, "type", "eventloopend");
		payload_new_timestamp(payload, "timestamp", &ps->timestamp);
		payload_finalize(payload);
		process_payload(payload);
		zmq_close(pubext);
		zmq_term(zmq_ctx);
	}
	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * handle) {
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq publisher");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "0.8");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Publishes Nagios data to 0MQ");

	neb_register_callback(NEBCALLBACK_HOST_CHECK_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_SERVICE_CHECK_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_ACKNOWLEDGEMENT_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_STATE_CHANGE_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_PROCESS_DATA, handle,
		0, handle_startup);
	neb_register_callback(NEBCALLBACK_COMMENT_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_DOWNTIME_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_PROGRAM_STATUS_DATA, handle,
		0, handle_nagdata);

	nagmq_handle = handle;
	args = strdup(localargs);

	return 0;
}
