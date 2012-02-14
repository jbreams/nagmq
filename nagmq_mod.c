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
#include <cJSON.h>

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

static void parse_timestamp(cJSON * out, char * key, struct timeval * tv) {
	cJSON * new_ts = cJSON_CreateObject();
	cJSON_AddNumberToObject(new_ts, "tv_sec", tv->tv_sec);
	cJSON_AddNumberToObject(new_ts, "tv_usec", tv->tv_usec);
	cJSON_AddItemToObject(out, key, new_ts);
}

static cJSON * parse_program_status(nebstruct_program_status_data * state) {
	cJSON * ret = cJSON_CreateObject();

	cJSON_AddStringToObject(ret, "type", "program_status");
	cJSON_AddNumberToObject(ret, "program_start", state->program_start);
	cJSON_AddNumberToObject(ret, "pid", state->pid);
	cJSON_AddNumberToObject(ret, "daemon_mode", state->daemon_mode);
	cJSON_AddNumberToObject(ret, "last_command_check", state->last_command_check);
	cJSON_AddNumberToObject(ret, "last_log_rotation", state->last_log_rotation);
	cJSON_AddNumberToObject(ret, "notifications_enabled", state->notifications_enabled);
	cJSON_AddNumberToObject(ret, "active_service_checks_enabled", state->active_service_checks_enabled);
	cJSON_AddNumberToObject(ret, "passive_service_checks_enabled", state->passive_service_checks_enabled);
	cJSON_AddNumberToObject(ret, "active_host_checks_enabled", state->active_host_checks_enabled);
	cJSON_AddNumberToObject(ret, "passive_host_checks_enabled", state->passive_host_checks_enabled);
	cJSON_AddNumberToObject(ret, "event_handlers_enabled", state->event_handlers_enabled);
	cJSON_AddNumberToObject(ret, "flap_detection_enabled", state->flap_detection_enabled);
	cJSON_AddNumberToObject(ret, "failure_prediction_enabled", state->failure_prediction_enabled);
	cJSON_AddNumberToObject(ret, "process_performance_data", state->process_performance_data);
	cJSON_AddNumberToObject(ret, "obsess_over_hosts", state->obsess_over_hosts);
	cJSON_AddNumberToObject(ret, "obsess_over_services", state->obsess_over_services);
	return ret;
}

static cJSON * parse_host_check(nebstruct_host_check_data * state) {
	cJSON * ret = cJSON_CreateObject();
	host * obj = find_host(state->host_name);

	cJSON_AddStringToObject(ret, "host_name", state->host_name);
	cJSON_AddNumberToObject(ret, "current_attempt", state->current_attempt);
	cJSON_AddNumberToObject(ret, "max_attempts", state->max_attempts);
	cJSON_AddNumberToObject(ret, "state", state->state);
	cJSON_AddNumberToObject(ret, "last_state", obj->last_state);
	cJSON_AddNumberToObject(ret, "last_hard_state", obj->last_hard_state);
	cJSON_AddNumberToObject(ret, "last_check", obj->last_check);
	cJSON_AddNumberToObject(ret, "last_state_change", obj->last_state_change);

	if(state->type == NEBTYPE_HOSTCHECK_INITIATE) {
		cJSON_AddStringToObject(ret, "type", "host_check_initiate");
		cJSON_AddStringToObject(ret, "command_name", state->command_name);
		cJSON_AddStringToObject(ret, "command_args", state->command_args);
		cJSON_AddStringToObject(ret, "command_line", state->command_line);
		cJSON_AddNumberToObject(ret, "has_been_checked", obj->has_been_checked);
		cJSON_AddNumberToObject(ret, "check_interval", obj->check_interval);
		cJSON_AddNumberToObject(ret, "retry_interval", obj->retry_interval);
		cJSON_AddNumberToObject(ret, "accept_passive_checks", obj->accept_passive_host_checks);
	} else if(state->type == NEBTYPE_HOSTCHECK_PROCESSED) {
		cJSON_AddStringToObject(ret, "type", "host_check_processed");
		cJSON_AddNumberToObject(ret, "timeout", state->timeout);
		parse_timestamp(ret, "start_time", &state->start_time);
		parse_timestamp(ret, "start_time", &state->end_time);
		cJSON_AddNumberToObject(ret, "early_timeout", state->early_timeout);
		cJSON_AddNumberToObject(ret, "execution_time", state->execution_time);
		cJSON_AddNumberToObject(ret, "latency", state->latency);
		cJSON_AddNumberToObject(ret, "return_code", state->return_code);
		cJSON_AddStringToObject(ret, "output", state->output);
		cJSON_AddStringToObject(ret, "long_output", state->long_output);
		cJSON_AddStringToObject(ret, "perf_data", state->perf_data);
	}
	return ret;
}

static cJSON * parse_service_check(nebstruct_service_check_data * state) {
	cJSON * ret = cJSON_CreateObject();
	service * obj = find_service(state->host_name, state->service_description);

	cJSON_AddStringToObject(ret, "host_name", state->host_name);
	cJSON_AddStringToObject(ret, "service_description", state->service_description);
	cJSON_AddNumberToObject(ret, "current_attempt", state->current_attempt);
	cJSON_AddNumberToObject(ret, "max_attempts", state->max_attempts);
	cJSON_AddNumberToObject(ret, "state", state->state);
	cJSON_AddNumberToObject(ret, "last_state", obj->last_state);
	cJSON_AddNumberToObject(ret, "last_hard_state", obj->last_hard_state);
	cJSON_AddNumberToObject(ret, "last_check", obj->last_check);
	cJSON_AddNumberToObject(ret, "last_state_change", obj->last_state_change);

	if(state->type == NEBTYPE_SERVICECHECK_INITIATE) {
		cJSON_AddStringToObject(ret, "type", "service_check_initiate");
		cJSON_AddStringToObject(ret, "command_name", state->command_name);
		cJSON_AddStringToObject(ret, "command_args", state->command_args);
		cJSON_AddStringToObject(ret, "command_line", state->command_line);
		cJSON_AddNumberToObject(ret, "has_been_checked", obj->has_been_checked);
		cJSON_AddNumberToObject(ret, "check_interval", obj->check_interval);
		cJSON_AddNumberToObject(ret, "retry_interval", obj->retry_interval);
		cJSON_AddNumberToObject(ret, "accept_passive_checks", obj->accept_passive_service_checks);
	} else if(state->type == NEBTYPE_SERVICECHECK_PROCESSED) {
		cJSON_AddStringToObject(ret, "type", "service_check_processed");
		parse_timestamp(ret, "start_time", &state->start_time);
		parse_timestamp(ret, "end_time", &state->end_time);
		cJSON_AddNumberToObject(ret, "early_timeout", state->early_timeout);
		cJSON_AddNumberToObject(ret, "execution_time", state->execution_time);
		cJSON_AddNumberToObject(ret, "latency", state->latency);
		cJSON_AddNumberToObject(ret, "return_code", state->return_code);
		cJSON_AddStringToObject(ret, "output", state->output);
		cJSON_AddStringToObject(ret, "long_output", state->long_output);
		cJSON_AddStringToObject(ret, "perf_data", state->perf_data);
		cJSON_AddNumberToObject(ret, "timeout", state->timeout);
	}
	return ret;
}

static cJSON * parse_acknowledgement(nebstruct_acknowledgement_data * state) {
	cJSON * ret = cJSON_CreateObject();

	cJSON_AddStringToObject(ret, "type", "acknowledgement");
	cJSON_AddStringToObject(ret, "host_name", state->host_name);
	cJSON_AddStringToObject(ret, "service_description", state->service_description);
	cJSON_AddNumberToObject(ret, "state", state->state);
	cJSON_AddStringToObject(ret, "author_name", state->author_name);
	cJSON_AddStringToObject(ret, "comment_data", state->comment_data);
	cJSON_AddNumberToObject(ret, "is_sticky", state->is_sticky);
	cJSON_AddNumberToObject(ret, "persistent_comment", state->persistent_comment);
	cJSON_AddNumberToObject(ret, "notify_contacts", state->notify_contacts);
	return ret;
}

static cJSON * parse_statechange(nebstruct_statechange_data * state) {
	cJSON * ret = cJSON_CreateObject();

	cJSON_AddStringToObject(ret, "type", "statechange");
	cJSON_AddStringToObject(ret, "host_name", state->host_name);
	cJSON_AddStringToObject(ret, "service_description", state->service_description);
	cJSON_AddNumberToObject(ret, "state", state->state);
	cJSON_AddNumberToObject(ret, "current_attempt", state->current_attempt);
	cJSON_AddNumberToObject(ret, "max_attempts", state->max_attempts);
	cJSON_AddStringToObject(ret, "output", state->output);
	return ret;
}

static cJSON * parse_comment(nebstruct_comment_data * state) {
	cJSON * ret = cJSON_CreateObject();

	if(state->type == NEBTYPE_COMMENT_ADD) {
		cJSON_AddStringToObject(ret, "type", "comment_add");
		cJSON_AddStringToObject(ret, "host_name", state->host_name);
		cJSON_AddStringToObject(ret, "service_description", state->service_description);
		cJSON_AddNumberToObject(ret, "entry_time", state->entry_time);
		cJSON_AddStringToObject(ret, "author_name", state->author_name);
		cJSON_AddStringToObject(ret, "comment_data", state->comment_data);
		cJSON_AddNumberToObject(ret, "persistent", state->persistent);
		cJSON_AddNumberToObject(ret, "source", state->source);
		cJSON_AddNumberToObject(ret, "expires", state->expires);
		cJSON_AddNumberToObject(ret, "expire_time", state->expire_time);
	} else if(state->type == NEBTYPE_COMMENT_DELETE) {
		cJSON_AddStringToObject(ret, "type", "comment_delete");
	}

	cJSON_AddNumberToObject(ret, "comment_id", state->comment_id);
	return ret;
}

static cJSON * parse_downtime(nebstruct_downtime_data * state) {
	cJSON * ret = cJSON_CreateObject();

	switch(state->type) {
		case NEBTYPE_DOWNTIME_ADD:
			cJSON_AddStringToObject(ret, "type", "downtime_add");
			break;
		case NEBTYPE_DOWNTIME_DELETE:
			cJSON_AddStringToObject(ret, "type", "downtime_delete");
			cJSON_AddNumberToObject(ret, "downtime_id", state->downtime_id);
			return ret;
		case NEBTYPE_DOWNTIME_START:
			cJSON_AddStringToObject(ret, "type", "downtime_start");
			break;
		case NEBTYPE_DOWNTIME_STOP:
			cJSON_AddStringToObject(ret, "type", "downtime_stop");
			break;
	}

	cJSON_AddStringToObject(ret, "host_name", state->host_name);
	cJSON_AddStringToObject(ret, "service_description", state->service_description);
	cJSON_AddNumberToObject(ret, "entry_time", state->entry_time);
	cJSON_AddStringToObject(ret, "author_name", state->author_name);
	cJSON_AddStringToObject(ret, "comment_data", state->comment_data);
	cJSON_AddNumberToObject(ret, "start_time", state->start_time);
	cJSON_AddNumberToObject(ret, "end_time", state->end_time);
	cJSON_AddNumberToObject(ret, "fixed", state->fixed);
	cJSON_AddNumberToObject(ret, "duration", state->duration);
	cJSON_AddNumberToObject(ret, "triggered_by", state->triggered_by);
	cJSON_AddNumberToObject(ret, "downtime_id", state->downtime_id);
	return ret;
}

static cJSON * parse_flapping(nebstruct_flapping_data * state) {
	cJSON * ret = cJSON_CreateObject();

	if(state->type == NEBTYPE_FLAPPING_START)
		cJSON_AddStringToObject(ret, "type", "flapping_start");
	else
		cJSON_AddStringToObject(ret, "type", "flapping_stop");
		
	cJSON_AddStringToObject(ret, "host_name", state->host_name);
	cJSON_AddStringToObject(ret, "service_description", state->service_description);
	cJSON_AddNumberToObject(ret, "percent_change", state->percent_change);
	cJSON_AddNumberToObject(ret, "high_threshold", state->high_threshold);
	cJSON_AddNumberToObject(ret, "low_threshold", state->low_threshold);
	cJSON_AddNumberToObject(ret, "comment_id", state->comment_id);
	return ret;
}

void free_cb(void * ptr, void * hint) {
	free(ptr);
}

static void process_payload(cJSON * payload) {
	zmq_msg_t type, dump;
	char * payloadstr;
	int rc;

	cJSON * jtype = cJSON_GetObjectItem(payload, "type");
	size_t slen = strlen(jtype->valuestring);
	zmq_msg_init_size(&type, slen);
	memcpy(zmq_msg_data(&type), jtype->valuestring, slen);
	rc = (zmq_send(pubext, &type, ZMQ_SNDMORE|ZMQ_NOBLOCK) == 0) ? 0 : errno;
	zmq_msg_close(&type);
	if(rc != 0) {
	//	syslog(LOG_ERR, "Error sending type header: %s",
	//		zmq_strerror(rc));
		cJSON_Delete(payload);
		return;
	}

	payloadstr = cJSON_PrintUnformatted(payload);
	zmq_msg_init_data(&dump, payloadstr, strlen(payloadstr), free_cb, NULL);
	if((rc = zmq_send(pubext, &dump, ZMQ_NOBLOCK)) != 0)
		syslog(LOG_ERR, "Error sending payload: %s",
			zmq_strerror(errno));
	zmq_msg_close(&dump);
	cJSON_Delete(payload);	
}

int handle_nagdata(int which, void * obj) {
	cJSON * payload = NULL;	
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

	parse_timestamp(payload, "timestamp", &raw->timestamp);
	process_payload(payload);
	return 0;
}

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	cJSON * payload;
	if (ps->type == NEBTYPE_PROCESS_EVENTLOOPSTART) {
		int numthreads = 1, rc;
		char * bindto = NULL;

		char * lock = (char*)args, *name, *val;
		while(*lock != '\0') {
			name = lock;
			while(*lock != ',' && *lock != '\0') {
				if(*lock == '=') {
					*lock = '\0';
					val = lock + 1;
				}
				lock++;
			}
			*lock = '\0';
			if(strcmp(name, "bind") == 0)
				bindto = val;
			else if(strcmp(name, "numthreads") == 0)
				numthreads = atoi(val);
		}

		zmq_ctx = zmq_init(numthreads);
		if(zmq_ctx == NULL) {
			syslog(LOG_ERR, "Error intializing ZMQ context: %s",
				zmq_strerror(errno));
			return -1;
		}

		pubext = zmq_socket(zmq_ctx, ZMQ_PUB);
		if(pubext == NULL) {
			syslog(LOG_ERR, "Error creating ZMQ socket: %s",
				zmq_strerror(errno));
			return -1;
		}

		rc = zmq_bind(pubext, bindto);
		if(rc != 0) {
			syslog(LOG_ERR, "Error binding to %s: %s",
				bindto, zmq_strerror(errno));
			return -1;
		}

		payload = cJSON_CreateObject();
		cJSON_AddStringToObject(payload, "type", "eventloopstart");
		parse_timestamp(payload, "timestamp", &ps->timestamp);
		process_payload(payload);
	} else if(ps->type == NEBTYPE_PROCESS_EVENTLOOPEND) {
		payload = cJSON_CreateObject();
		cJSON_AddStringToObject(payload, "type", "eventloopend");
		parse_timestamp(payload, "timestamp", &ps->timestamp);
		process_payload(payload);
		zmq_close(pubext);
		zmq_term(zmq_ctx);
	}
	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * handle) {
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq sink");
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
