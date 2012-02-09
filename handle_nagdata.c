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
#include <zmq.h>
#include <jansson.h>

void * zmq_ctx = NULL;
void * pub_sock = NULL;
void * nagmq_handle = NULL;

NEB_API_VERSION(CURRENT_NEB_API_VERSION)

int nebmodule_deinit(int flags, int reason) {
	zmq_close(pub_sock);
	zmq_term(zmq_ctx);
	neb_deregister_module_callbacks(nagmq_handle);
	return 0;
}

static json_t * parse_timestamp(struct timeval * tv) {
	json_t * ret = json_object();
	json_object_set_new(ret, "tv_sec", json_integer(tv->tv_sec));
	json_object_set_new(ret, "tv_usec", json_integer(tv->tv_usec));
	return ret;
}

static json_t * parse_host_check(nebstruct_host_check_data * state) {
	json_t * ret = json_object();

	json_object_set_new(ret, "type", json_string("host_check"));
	json_object_set_new(ret, "host_name", json_string(state->host_name));
	json_object_set_new(ret, "current_attempt", json_integer(state->current_attempt));
	json_object_set_new(ret, "max_attempts", json_integer(state->max_attempts));
	json_object_set_new(ret, "state", json_integer(state->state));
	json_object_set_new(ret, "timeout", json_integer(state->timeout));
	json_object_set_new(ret, "command_name", json_string(state->command_name));
	json_object_set_new(ret, "command_args", json_string(state->command_args));
	json_object_set_new(ret, "command_line", json_string(state->command_line));
	json_object_set_new(ret, "start_time", parse_timestamp(&state->start_time));
	json_object_set_new(ret, "end_time", parse_timestamp(&state->end_time));
	json_object_set_new(ret, "early_timeout", json_integer(state->early_timeout));
	json_object_set_new(ret, "execution_time", json_real(state->execution_time));
	json_object_set_new(ret, "latency", json_real(state->latency));
	json_object_set_new(ret, "return_code", json_integer(state->return_code));
	json_object_set_new(ret, "output", json_string(state->output));
	json_object_set_new(ret, "long_output", json_string(state->long_output));
	json_object_set_new(ret, "perf_data", json_string(state->perf_data));
	return ret;
}

static json_t * parse_service_check(nebstruct_service_check_data * state) {
	json_t * ret = json_object();

	json_object_set_new(ret, "type", json_string("service_check"));
	json_object_set_new(ret, "host_name", json_string(state->host_name));
	json_object_set_new(ret, "service_description", json_string(state->service_description));
	json_object_set_new(ret, "current_attempt", json_integer(state->current_attempt));
	json_object_set_new(ret, "max_attempts", json_integer(state->max_attempts));
	json_object_set_new(ret, "state", json_integer(state->state));
	json_object_set_new(ret, "timeout", json_integer(state->timeout));
	json_object_set_new(ret, "command_name", json_string(state->command_name));
	json_object_set_new(ret, "command_args", json_string(state->command_args));
	json_object_set_new(ret, "command_line", json_string(state->command_line));
	json_object_set_new(ret, "start_time", parse_timestamp(&state->start_time));
	json_object_set_new(ret, "end_time", parse_timestamp(&state->end_time));
	json_object_set_new(ret, "early_timeout", json_integer(state->early_timeout));
	json_object_set_new(ret, "execution_time", json_real(state->execution_time));
	json_object_set_new(ret, "latency", json_real(state->latency));
	json_object_set_new(ret, "return_code", json_integer(state->return_code));
	json_object_set_new(ret, "output", json_string(state->output));
	json_object_set_new(ret, "long_output", json_string(state->long_output));
	json_object_set_new(ret, "perf_data", json_string(state->perf_data));
	return ret;
}

static json_t * parse_program_status(nebstruct_program_status_data * state) {
	json_t * ret = json_object();

	json_object_set_new(ret, "type", json_string("program_status"));
	json_object_set_new(ret, "program_start", json_integer(state->program_start));
	json_object_set_new(ret, "pid", json_integer(state->pid));
	json_object_set_new(ret, "daemon_mode", json_integer(state->daemon_mode));
	json_object_set_new(ret, "last_command_check", json_integer(state->last_command_check));
	json_object_set_new(ret, "last_log_rotation", json_integer(state->last_log_rotation));
	json_object_set_new(ret, "notifications_enabled", json_integer(state->notifications_enabled));
	json_object_set_new(ret, "active_service_checks_enabled", json_integer(state->active_service_checks_enabled));
	json_object_set_new(ret, "passive_service_checks_enabled", json_integer(state->passive_service_checks_enabled));
	json_object_set_new(ret, "active_host_checks_enabled", json_integer(state->active_host_checks_enabled));
	json_object_set_new(ret, "passive_host_checks_enabled", json_integer(state->passive_host_checks_enabled));
	json_object_set_new(ret, "event_handlers_enabled", json_integer(state->event_handlers_enabled));
	json_object_set_new(ret, "flap_detection_enabled", json_integer(state->flap_detection_enabled));
	json_object_set_new(ret, "failure_prediction_enabled", json_integer(state->failure_prediction_enabled));
	json_object_set_new(ret, "process_performance_data", json_integer(state->process_performance_data));
	json_object_set_new(ret, "obsess_over_hosts", json_integer(state->obsess_over_hosts));
	json_object_set_new(ret, "obsess_over_services", json_integer(state->obsess_over_services));
	json_object_set_new(ret, "modified_host_attributes", json_integer(state->modified_host_attributes));
	json_object_set_new(ret, "modified_service_attributes", json_integer(state->modified_service_attributes));
	json_object_set_new(ret, "global_host_event_handler", json_string(state->global_host_event_handler));
	json_object_set_new(ret, "global_service_event_handler", json_string(state->global_service_event_handler));
	return ret;
}

static json_t * parse_host_status(nebstruct_host_status_data * obj) {
	host * state = obj->object_ptr;
	json_t * ret = json_object();

	json_object_set_new(ret, "type", json_string("host_status"));
	json_object_set_new(ret, "name", json_string(state->name));
	json_object_set_new(ret, "plugin_output", json_string(state->plugin_output));
	json_object_set_new(ret, "long_plugin_output", json_string(state->long_plugin_output));
	json_object_set_new(ret, "perf_data", json_string(state->perf_data));
	json_object_set_new(ret, "has_been_checked", json_integer(state->has_been_checked));
	json_object_set_new(ret, "should_be_scheduled", json_integer(state->should_be_scheduled));
	json_object_set_new(ret, "current_attempt", json_integer(state->current_attempt));
	json_object_set_new(ret, "max_attempts", json_integer(state->max_attempts));
	json_object_set_new(ret, "last_check", json_integer(state->last_check));
	json_object_set_new(ret, "next_check", json_integer(state->next_check));
	json_object_set_new(ret, "check_options", json_integer(state->check_options));
	json_object_set_new(ret, "last_state_change", json_integer(state->last_state_change));
	json_object_set_new(ret, "last_hard_state_change", json_integer(state->last_hard_state_change));
	json_object_set_new(ret, "last_hard_state", json_integer(state->last_hard_state));
	json_object_set_new(ret, "last_time_up", json_integer(state->last_time_up));
	json_object_set_new(ret, "last_time_down", json_integer(state->last_time_down));
	json_object_set_new(ret, "last_time_unreachable", json_integer(state->last_time_unreachable));
	json_object_set_new(ret, "no_more_notifications", json_integer(state->no_more_notifications));
	json_object_set_new(ret, "notifications_enabled", json_integer(state->notifications_enabled));
	json_object_set_new(ret, "problem_has_been_acknowledged", json_integer(state->problem_has_been_acknowledged));
	json_object_set_new(ret, "current_notification_number", json_integer(state->current_notification_number));
	json_object_set_new(ret, "accept_passive_host_checks", json_integer(state->accept_passive_host_checks));
	json_object_set_new(ret, "event_handler_enabled", json_integer(state->event_handler_enabled));
	json_object_set_new(ret, "checks_enabled", json_integer(state->checks_enabled));
	json_object_set_new(ret, "flap_detection_enabled", json_integer(state->flap_detection_enabled));
	json_object_set_new(ret, "is_flapping", json_integer(state->is_flapping));
	json_object_set_new(ret, "percent_state_change", json_real(state->percent_state_change));
	json_object_set_new(ret, "latency", json_real(state->latency));
	json_object_set_new(ret, "execution_time", json_real(state->execution_time));
	json_object_set_new(ret, "scheduled_downtime_depth", json_integer(state->scheduled_downtime_depth));
	json_object_set_new(ret, "failure_prediction_enabled", json_integer(state->failure_prediction_enabled));
	json_object_set_new(ret, "process_performance_data", json_integer(state->process_performance_data));
	json_object_set_new(ret, "obsess_over_host", json_integer(state->obsess_over_host));
	return ret;
}

static json_t * parse_service_status(nebstruct_service_status_data * obj) {
	json_t * ret = json_object();
	service * state = obj->object_ptr;

	json_object_set_new(ret, "type", json_string("service_status"));
	json_object_set_new(ret, "host_name", json_string(state->host_name));
	json_object_set_new(ret, "description", json_string(state->description));
	json_object_set_new(ret, "plugin_output", json_string(state->plugin_output));
	json_object_set_new(ret, "long_plugin_output", json_string(state->long_plugin_output));
	json_object_set_new(ret, "perf_data", json_string(state->perf_data));
	json_object_set_new(ret, "max_attempts", json_integer(state->max_attempts));
	json_object_set_new(ret, "current_attempt", json_integer(state->current_attempt));
	json_object_set_new(ret, "has_been_checked", json_integer(state->has_been_checked));
	json_object_set_new(ret, "should_be_scheduled", json_integer(state->should_be_scheduled));
	json_object_set_new(ret, "last_check", json_integer(state->last_check));
	json_object_set_new(ret, "next_check", json_integer(state->next_check));
	json_object_set_new(ret, "check_options", json_integer(state->check_options));
	json_object_set_new(ret, "checks_enabled", json_integer(state->checks_enabled));
	json_object_set_new(ret, "last_state_change", json_integer(state->last_state_change));
	json_object_set_new(ret, "last_hard_state_change", json_integer(state->last_hard_state_change));
	json_object_set_new(ret, "last_hard_state", json_integer(state->last_hard_state));
	json_object_set_new(ret, "last_time_ok", json_integer(state->last_time_ok));
	json_object_set_new(ret, "last_time_warning", json_integer(state->last_time_warning));
	json_object_set_new(ret, "last_time_unknown", json_integer(state->last_time_unknown));
	json_object_set_new(ret, "last_time_critical", json_integer(state->last_time_critical));
	json_object_set_new(ret, "last_notification", json_integer(state->last_notification));
	json_object_set_new(ret, "next_notification", json_integer(state->next_notification));
	json_object_set_new(ret, "no_more_notifications", json_integer(state->no_more_notifications));
	json_object_set_new(ret, "notifications_enabled", json_integer(state->notifications_enabled));
	json_object_set_new(ret, "problem_has_been_acknowledged", json_integer(state->problem_has_been_acknowledged));
	json_object_set_new(ret, "current_notification_number", json_integer(state->current_notification_number));
	json_object_set_new(ret, "accept_passive_service_checks", json_integer(state->accept_passive_service_checks));
	json_object_set_new(ret, "event_handler_enabled", json_integer(state->event_handler_enabled));
	json_object_set_new(ret, "flap_detection_enabled", json_integer(state->flap_detection_enabled));
	json_object_set_new(ret, "is_flapping", json_integer(state->is_flapping));
	json_object_set_new(ret, "percent_state_change", json_real(state->percent_state_change));
	json_object_set_new(ret, "latency", json_real(state->latency));
	json_object_set_new(ret, "execution_time", json_real(state->execution_time));
	json_object_set_new(ret, "scheduled_downtime_depth", json_integer(state->scheduled_downtime_depth));
	json_object_set_new(ret, "failure_prediction_enabled", json_integer(state->failure_prediction_enabled));
	json_object_set_new(ret, "process_performance_data", json_integer(state->process_performance_data));
	json_object_set_new(ret, "obsess_over_service", json_integer(state->obsess_over_service));

	return ret;
}

static json_t * parse_acknowledgement(nebstruct_acknowledgement_data * state) {
	json_t * ret = json_object();

	json_object_set_new(ret, "type", json_string("acknowledgement"));
	json_object_set_new(ret, "host_name", json_string(state->host_name));
	json_object_set_new(ret, "service_description", json_string(state->service_description));
	json_object_set_new(ret, "state", json_integer(state->state));
	json_object_set_new(ret, "author_name", json_string(state->author_name));
	json_object_set_new(ret, "comment_data", json_string(state->comment_data));
	json_object_set_new(ret, "is_sticky", json_integer(state->is_sticky));
	json_object_set_new(ret, "persistent_comment", json_integer(state->persistent_comment));
	json_object_set_new(ret, "notify_contacts", json_integer(state->notify_contacts));
	return ret;
}

static json_t * parse_statechange(nebstruct_statechange_data * state) {
	json_t * ret = json_object();

	json_object_set_new(ret, "type", json_string("statechange"));
	json_object_set_new(ret, "host_name", json_string(state->host_name));
	json_object_set_new(ret, "service_description", json_string(state->service_description));
	json_object_set_new(ret, "state", json_integer(state->state));
	json_object_set_new(ret, "current_attempt", json_integer(state->current_attempt));
	json_object_set_new(ret, "max_attempts", json_integer(state->max_attempts));
	json_object_set_new(ret, "output", json_string(state->output));
	return ret;
}

void free_cb(void * ptr, void * hint) {
	free(ptr);
}

int handle_nagdata(int which, void * obj) {
	json_t * payload = NULL;
	zmq_msg_t payload_msg;
	int rc;

	switch(which) {
	case NEBCALLBACK_HOST_CHECK_DATA:
		payload = parse_host_check(obj);
		break;
	case NEBCALLBACK_SERVICE_CHECK_DATA:
		payload = parse_service_check(obj);
		break;
	case NEBCALLBACK_PROGRAM_STATUS_DATA:
		payload = parse_program_status(obj);
		break;
	case NEBCALLBACK_HOST_STATUS_DATA:
		payload = parse_host_status(obj);
		break;
	case NEBCALLBACK_SERVICE_STATUS_DATA:
		payload = parse_service_status(obj);
		break;
	case NEBCALLBACK_ACKNOWLEDGEMENT_DATA:
		payload = parse_acknowledgement(obj);
		break;
	case NEBCALLBACK_STATE_CHANGE_DATA:
		payload = parse_statechange(obj);
		break;
	}

	if(payload == NULL)
		return 0;

	/*json_t * type = json_object_get(payload, "type");
	//syslog(LOG_INFO, "Sending %s payload", json_string_value(type));
	char * typestr = strdup(json_string_value(type));

	zmq_msg_init_data(&header, typestr, strlen(typestr),
		free_cb, NULL);
	rc = zmq_send(pub_sock, &header, ZMQ_SNDMORE);
	zmq_msg_close(&header);
	if(rc != 0)
		syslog(LOG_ERR, "Error sending header %s: %s", json_string_value(type),
			zmq_strerror(errno));
	*/

	char * payloadstr = json_dumps(payload, JSON_COMPACT);
	size_t plstrlen = strlen(payloadstr);
	zmq_msg_init_size(&payload_msg, plstrlen);
	memcpy(zmq_msg_data(&payload_msg), payloadstr, plstrlen);
	free(payloadstr);
	rc = zmq_send(pub_sock, &payload_msg, 0);
        if(rc != 0)  
                syslog(LOG_ERR, "Error payload %s", zmq_strerror(errno));
	else
		syslog(LOG_INFO, "Send message to %p!", pub_sock);
	zmq_msg_close(&payload_msg);
	return 0;
}

int nebmodule_init(int flags, char * args, nebmodule * handle) {
	const int linger = 0;
        neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq sink");
        neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
        neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "0.1");
        neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
        neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
                "Sink for publishing nagios data to ZMQ");
                        
        zmq_ctx = zmq_init(1);
        if(zmq_ctx == NULL) {
		syslog(LOG_ERR, "Error initializing ZMQ context for NagMQ: %s", zmq_strerror(errno));
                return -1;
	} else
		syslog(LOG_INFO, "Initialized ZMQ context %p", zmq_ctx);
        pub_sock = zmq_socket(zmq_ctx, ZMQ_PUB);
        if(pub_sock == NULL) {
		syslog(LOG_ERR, "Error initialzing socket: %s", zmq_strerror(errno));
                zmq_term(zmq_ctx);
                return -1;
        } else
		syslog(LOG_INFO, "Initialized ZMQ socket %p", pub_sock);
	zmq_setsockopt(pub_sock, ZMQ_LINGER, &linger, sizeof(linger));       
 
        char * lock = args, *name, *val;
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
                if(strcmp(name, "bind") == 0) {
			syslog(LOG_ERR, "NagMQ is binding to %s", val);
			if(zmq_bind(pub_sock, val) == 0)
				syslog(LOG_INFO, "Bound ZMQ socket %p to %s", pub_sock, val);
			else
				syslog(LOG_ERR, "Error binding ZMQ socket %p to %s: %s",
					pub_sock, val, zmq_strerror(errno));
                }
        }
        
        neb_register_callback(NEBCALLBACK_HOST_CHECK_DATA, handle,
                0, handle_nagdata);
        neb_register_callback(NEBCALLBACK_SERVICE_CHECK_DATA, handle,
                0, handle_nagdata);
        neb_register_callback(NEBCALLBACK_PROGRAM_STATUS_DATA, handle,
                0, handle_nagdata);
        neb_register_callback(NEBCALLBACK_HOST_STATUS_DATA, handle,
                0, handle_nagdata);
        neb_register_callback(NEBCALLBACK_SERVICE_STATUS_DATA, handle,
                0, handle_nagdata);
        neb_register_callback(NEBCALLBACK_ACKNOWLEDGEMENT_DATA, handle,
                0, handle_nagdata);
        neb_register_callback(NEBCALLBACK_STATE_CHANGE_DATA, handle,
                0, handle_nagdata);

        nagmq_handle = handle;

        return 0;
}
