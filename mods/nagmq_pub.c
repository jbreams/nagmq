#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#define NSCORE 1
#include "nebstructs.h"
#include "nebcallbacks.h"
#include "nebmodules.h"
#include "nebmods.h"
#include "nagios.h"
#include "objects.h"
#include "broker.h"
#include "neberrors.h"
#include <zmq.h>
#include <errno.h>
#include "json.h"
#include "common.h"

extern nebmodule * handle;
void * pubext;
#define OR_HOSTCHECK_INITIATE 0
#define OR_SERVICECHECK_INITIATE 1
#define OR_EVENTHANDLER_START 2
#define OR_NOTIFICATION_START 3
#define OR_MAX 4
static int overrides[OR_MAX];

static struct payload * parse_program_status(nebstruct_program_status_data * state) {
	struct payload * ret = payload_new();	

	payload_new_string(ret, "type", "program_status");
	payload_new_integer(ret, "program_start", state->program_start);
	payload_new_integer(ret, "pid", state->pid);
	payload_new_integer(ret, "daemon_mode", state->daemon_mode);
	payload_new_integer(ret, "last_command_check", state->last_command_check);
	payload_new_integer(ret, "last_log_rotation", state->last_log_rotation);
	payload_new_boolean(ret, "notifications_enabled", state->notifications_enabled);
	payload_new_boolean(ret, "active_service_checks_enabled", state->active_service_checks_enabled);
	payload_new_boolean(ret, "passive_service_checks_enabled", state->passive_service_checks_enabled);
	payload_new_boolean(ret, "active_host_checks_enabled", state->active_host_checks_enabled);
	payload_new_boolean(ret, "passive_host_checks_enabled", state->passive_host_checks_enabled);
	payload_new_boolean(ret, "event_handlers_enabled", state->event_handlers_enabled);
	payload_new_boolean(ret, "flap_detection_enabled", state->flap_detection_enabled);
	payload_new_boolean(ret, "failure_prediction_enabled", state->failure_prediction_enabled);
	payload_new_boolean(ret, "process_performance_data", state->process_performance_data);
	payload_new_boolean(ret, "obsess_over_hosts", state->obsess_over_hosts);
	payload_new_boolean(ret, "obsess_over_services", state->obsess_over_services);
	return ret;
}

static struct payload * parse_event_handler(nebstruct_event_handler_data * state) {
	struct payload * ret = payload_new();
	host * host_obj = NULL;
	service * service_obj = NULL;
	if(state->service_description) {
		service_obj = (service*)state->object_ptr;
		host_obj = service_obj->host_ptr;
	} else
		host_obj = (host*)state->object_ptr;

	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "state", state->state);
	if(service_obj) {
		payload_new_integer(ret, "last_state", service_obj->last_state);
		payload_new_statestr(ret, "last_state_str", service_obj->last_state, service_obj->has_been_checked, 1);
		payload_new_integer(ret, "last_hard_state", service_obj->last_hard_state);
		payload_new_statestr(ret, "last_hard_state_str", service_obj->last_hard_state, service_obj->has_been_checked, 1);
		payload_new_integer(ret, "last_check", service_obj->last_check);
		payload_new_integer(ret, "last_state_change", service_obj->last_state_change);
		payload_new_statestr(ret, "state_str", state->state, service_obj->has_been_checked, 1);
	} else {
		payload_new_integer(ret, "last_state", host_obj->last_state);
		payload_new_statestr(ret, "last_state_str", host_obj->last_state, host_obj->has_been_checked, 0);
		payload_new_integer(ret, "last_hard_state", host_obj->last_hard_state);
		payload_new_statestr(ret, "last_hard_state_str", host_obj->last_hard_state, host_obj->has_been_checked, 0);
		payload_new_integer(ret, "last_check", host_obj->last_check);
		payload_new_integer(ret, "last_state_change", host_obj->last_state_change);
		payload_new_statestr(ret, "state_str", state->state, host_obj->has_been_checked, 0);
	}

	if(state->type == NEBTYPE_EVENTHANDLER_START) {
		payload_new_string(ret, "type", "eventhandler_start");
		payload_new_string(ret, "command_name", state->command_name);
		payload_new_string(ret, "command_args", state->command_args);
		payload_new_string(ret, "command_line", state->command_line);
	} else {
		payload_new_string(ret, "type", "eventhandler_stop");
		payload_new_integer(ret, "timeout", state->timeout);
		payload_new_timestamp(ret, "start_time", &state->start_time);
		payload_new_timestamp(ret, "end_time", &state->end_time);
		payload_new_integer(ret, "early_timeout", state->early_timeout);
		payload_new_double(ret, "execution_time", state->execution_time);
		payload_new_integer(ret, "return_code", state->return_code);
		payload_new_string(ret, "output", state->output);
	}
	return ret;
}

// Stupid Nagios 3.x global variable
extern check_result check_result_info;

static struct payload * parse_host_check(nebstruct_host_check_data * state) {
	struct payload * ret = payload_new();
	host * obj = (host*)state->object_ptr; 

	payload_new_string(ret, "host_name", state->host_name);
	payload_new_integer(ret, "check_type", state->check_type);
	payload_new_integer(ret, "check_options", check_result_info.check_options);
	payload_new_integer(ret, "scheduled_check", check_result_info.scheduled_check);
	payload_new_integer(ret, "reschedule_check", check_result_info.reschedule_check);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_integer(ret, "state", state->state);
	payload_new_statestr(ret, "state_str", state->state, obj->has_been_checked, 0);
	payload_new_integer(ret, "last_state", obj->last_state);
	payload_new_statestr(ret, "last_state_str", obj->last_state, obj->has_been_checked, 0);
	payload_new_integer(ret, "last_hard_state", obj->last_hard_state);
	payload_new_statestr(ret, "last_hard_state_str", obj->last_hard_state, obj->has_been_checked, 0);
	payload_new_integer(ret, "last_check", obj->last_check);
	payload_new_integer(ret, "last_state_change", obj->last_state_change);
	payload_new_double(ret, "latency", state->latency);
	payload_new_integer(ret, "timeout", state->timeout);

	if(state->type == NEBTYPE_HOSTCHECK_INITIATE) {
		payload_new_string(ret, "type", "host_check_initiate");
		payload_new_string(ret, "command_name", state->command_name);
		payload_new_string(ret, "command_args", state->command_args);
		payload_new_string(ret, "command_line", state->command_line);
		payload_new_boolean(ret, "has_been_checked", obj->has_been_checked);
		payload_new_integer(ret, "check_interval", obj->check_interval);
		payload_new_integer(ret, "retry_interval", obj->retry_interval);
		payload_new_boolean(ret, "accept_passive_checks", obj->accept_passive_host_checks);
	} else if(state->type == NEBTYPE_HOSTCHECK_PROCESSED) {
		payload_new_string(ret, "type", "host_check_processed");
		payload_new_timestamp(ret, "start_time", &state->start_time);
		payload_new_timestamp(ret, "end_time", &state->end_time);
		payload_new_integer(ret, "early_timeout", state->early_timeout);
		payload_new_double(ret, "execution_time", state->execution_time);
		payload_new_integer(ret, "return_code", state->return_code);
		payload_new_string(ret, "output", state->output);
		payload_new_string(ret, "long_output", state->long_output);
		payload_new_string(ret, "perf_data", state->perf_data);
	}
	return ret;
}

static struct payload * parse_service_check(nebstruct_service_check_data * state) {
	struct payload * ret = payload_new();
	service * obj = (service*)state->object_ptr;

	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "check_type", state->check_type);
	payload_new_integer(ret, "check_options", check_result_info.check_options);
	payload_new_integer(ret, "scheduled_check", check_result_info.scheduled_check);
	payload_new_integer(ret, "reschedule_check", check_result_info.reschedule_check);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_integer(ret, "state", state->state);
	payload_new_statestr(ret, "state_str", state->state, obj->has_been_checked, 1);
	payload_new_integer(ret, "last_state", obj->last_state);
	payload_new_statestr(ret, "last_state_str", obj->last_state, obj->has_been_checked, 1);
	payload_new_integer(ret, "last_hard_state", obj->last_hard_state);
	payload_new_statestr(ret, "last_hard_state_str", obj->last_hard_state, obj->has_been_checked, 1);
	payload_new_integer(ret, "last_check", obj->last_check);
	payload_new_integer(ret, "last_state_change", obj->last_state_change);
	payload_new_double(ret, "latency", state->latency);
	payload_new_integer(ret, "timeout", state->timeout);

	if(state->type == NEBTYPE_SERVICECHECK_INITIATE) {
		payload_new_string(ret, "type", "service_check_initiate");
		payload_new_string(ret, "command_name", state->command_name);
		payload_new_string(ret, "command_args", state->command_args);
		payload_new_string(ret, "command_line", state->command_line);
		payload_new_boolean(ret, "has_been_checked", obj->has_been_checked);
		payload_new_integer(ret, "check_interval", obj->check_interval);
		payload_new_integer(ret, "retry_interval", obj->retry_interval);
		payload_new_boolean(ret, "accept_passive_checks", obj->accept_passive_service_checks);
	} else if(state->type == NEBTYPE_SERVICECHECK_PROCESSED) {
		payload_new_string(ret, "type", "service_check_processed");
		payload_new_timestamp(ret, "start_time", &state->start_time);
		payload_new_timestamp(ret, "end_time", &state->end_time);
		payload_new_integer(ret, "early_timeout", state->early_timeout);
		payload_new_double(ret, "execution_time", state->execution_time);
		payload_new_integer(ret, "return_code", state->return_code);
		payload_new_string(ret, "output", state->output);
		payload_new_string(ret, "long_output", state->long_output);
		payload_new_string(ret, "perf_data", state->perf_data);
	}
	return ret;
}

static struct payload * parse_acknowledgement(nebstruct_acknowledgement_data * state) {
	struct payload * ret = payload_new();

	payload_new_string(ret, "type", "acknowledgement");
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "state", state->state);
	payload_new_statestr(ret, "state_str", state->state, 1, state->service_description ? 1:0);
	payload_new_integer(ret, "acknowledgement_type", state->acknowledgement_type);
	payload_new_string(ret, "author_name", state->author_name);
	payload_new_string(ret, "comment_data", state->comment_data);
	payload_new_boolean(ret, "is_sticky", state->is_sticky);
	payload_new_boolean(ret, "persistent_comment", state->persistent_comment);
	payload_new_boolean(ret, "notify_contacts", state->notify_contacts);
	return ret;
}

static struct payload * parse_statechange(nebstruct_statechange_data * state) {
	struct payload * ret = payload_new();
	host * host_target = NULL;
	service * service_target = NULL;
	if(state->service_description) {
		service_target = (service*)state->object_ptr;
		host_target = service_target->host_ptr;
	} else
		host_target = (host*)state->object_ptr;

	payload_new_string(ret, "type", "statechange");
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "state", state->state);
	payload_new_integer(ret, "state_type", state->state_type);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_string(ret, "output", state->output);
	if(service_target) {
		payload_new_integer(ret, "last_state", service_target->last_state);
		payload_new_statestr(ret, "last_state_str", service_target->last_state, service_target->has_been_checked, 1);
		payload_new_statestr(ret, "last_hard_state_str", service_target->last_hard_state, service_target->has_been_checked, 1);
		payload_new_integer(ret, "last_hard_state", service_target->last_hard_state);
		payload_new_integer(ret, "last_check", service_target->last_check);
		payload_new_integer(ret, "last_state_change", service_target->last_state_change);
		payload_new_boolean(ret, "is_flapping", service_target->is_flapping);
		payload_new_boolean(ret, "problem_has_been_acknowledged", service_target->problem_has_been_acknowledged);
		payload_new_statestr(ret, "state_str", state->state, service_target->has_been_checked, 1);
	} else {
		payload_new_integer(ret, "last_state", host_target->last_state);
		payload_new_integer(ret, "last_hard_state", host_target->last_hard_state);
		payload_new_statestr(ret, "last_state_str", host_target->last_state, host_target->has_been_checked, 0);
		payload_new_statestr(ret, "last_hard_state_str", host_target->last_hard_state, host_target->has_been_checked, 0);
		payload_new_integer(ret, "last_check", host_target->last_check);
		payload_new_integer(ret, "last_state_change", host_target->last_state_change);
		payload_new_boolean(ret, "is_flapping", host_target->is_flapping);
		payload_new_boolean(ret, "problem_has_been_acknowledged", host_target->problem_has_been_acknowledged);
		payload_new_statestr(ret, "state_str", state->state, host_target->has_been_checked, 0);
	}
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
		payload_new_boolean(ret, "persistent", state->persistent);
		payload_new_integer(ret, "source", state->source);
		payload_new_boolean(ret, "expires", state->expires);
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
	payload_new_boolean(ret, "fixed", state->fixed);
	payload_new_integer(ret, "duration", state->duration);
	payload_new_integer(ret, "triggered_by", state->triggered_by);
	payload_new_integer(ret, "downtime_id", state->downtime_id);
	return ret;
}

static struct payload * parse_notification(nebstruct_notification_data * state) {
	struct payload * ret = payload_new();
	service * service_obj = NULL;
	host * host_obj;

	if(state->service_description)
		service_obj = (service*)state->object_ptr;
	else
		host_obj = (host*)state->object_ptr;

	if(state->type == NEBTYPE_NOTIFICATION_START)
		payload_new_string(ret, "type", "notification_start");
	else if(state->type == NEBTYPE_NOTIFICATION_END)
		payload_new_string(ret, "type", "notification_end");
	payload_new_timestamp(ret, "start_time", &state->start_time);
	payload_new_timestamp(ret, "end_time", &state->end_time);
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "state", state->state);
	payload_new_string(ret, "output", state->output);
	payload_new_string(ret, "ack_author", state->ack_author);
	payload_new_string(ret, "ack_data", state->ack_data);
	payload_new_boolean(ret, "escalated", state->escalated);
	payload_new_integer(ret, "contacts_notified", state->contacts_notified);

	contactgroupsmember * cgtmp;
	contactsmember * ctmp;
	if(service_obj) {
		payload_new_integer(ret, "current_notification_number", service_obj->current_notification_number);
		payload_new_integer(ret, "current_notification_id", service_obj->current_notification_id);
		payload_new_integer(ret, "last_state", service_obj->last_state);
		payload_new_integer(ret, "last_hard_state", service_obj->last_hard_state);
		payload_new_statestr(ret, "last_state_str", service_obj->last_state, service_obj->has_been_checked, 1);
		payload_new_statestr(ret, "last_hard_state_str", service_obj->last_hard_state, service_obj->has_been_checked, 1);
		payload_new_integer(ret, "last_check", service_obj->last_check);
		payload_new_integer(ret, "last_state_change", service_obj->last_state_change);
		payload_new_integer(ret, "last_notification", service_obj->last_notification);
		payload_new_statestr(ret, "state_str", state->state, service_obj->has_been_checked, 1);
		cgtmp = service_obj->contact_groups;
		ctmp = service_obj->contacts;
	} else {
		payload_new_integer(ret, "current_notification_number", host_obj->current_notification_number);
		payload_new_integer(ret, "current_notification_id", host_obj->current_notification_id);
		payload_new_integer(ret, "last_state", host_obj->last_state);
		payload_new_integer(ret, "last_hard_state", host_obj->last_hard_state);
		payload_new_statestr(ret, "last_state_str", host_obj->last_state, host_obj->has_been_checked, 0);
		payload_new_statestr(ret, "last_hard_state_str", host_obj->last_hard_state, host_obj->has_been_checked, 0);
		payload_new_integer(ret, "last_check", host_obj->last_check);
		payload_new_integer(ret, "last_state_change", host_obj->last_state_change);
		payload_new_integer(ret, "last_notification", host_obj->last_host_notification);
		payload_new_statestr(ret, "state_str", state->state, host_obj->has_been_checked, 1);
		cgtmp = host_obj->contact_groups;
		ctmp = host_obj->contacts;
	}

	payload_start_array(ret, "contacts");
	while(ctmp) {
		payload_new_string(ret, NULL, ctmp->contact_name);
		ctmp = ctmp->next;
	}
	payload_end_array(ret);

	payload_start_array(ret, "contact_groups");
	while(cgtmp) {
		payload_new_string(ret, NULL, cgtmp->group_name);
		cgtmp = cgtmp->next;
	}
	payload_end_array(ret);

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

static struct payload * parse_adaptivechange(nebstruct_adaptive_host_data * state) {
	nebstruct_adaptive_service_data * svcstate = NULL;
	service * svc = NULL;
	host * hst = NULL;
	if(state->type == NEBTYPE_ADAPTIVESERVICE_UPDATE)
		svcstate = (nebstruct_adaptive_service_data *)state;
	else if(state->type != NEBTYPE_ADAPTIVEHOST_UPDATE)
		return NULL;

	struct payload * ret = payload_new();
	if(svcstate) {
		svc = (service*)svcstate->object_ptr;
		payload_new_string(ret, "type", "adaptiveservice_update");
		if(svc) {
			payload_new_string(ret, "host_name", svc->host_name);
			payload_new_string(ret, "service_description", svc->description);
		}
	} else {
		hst = (host*)state->object_ptr;
		payload_new_string(ret, "type", "adaptivehost_update");
		if(hst)
			payload_new_string(ret, "host_name", hst->name);
	}

	switch(state->modified_attribute) {
		case MODATTR_NOTIFICATIONS_ENABLED:
			payload_new_string(ret, "attr", "notifications_enabled");
			if(svc)
				payload_new_boolean(ret, "notifications_enabled",
					svc->notifications_enabled);
			else if(hst)
				payload_new_boolean(ret, "notifications_enabled",
					hst->notifications_enabled);
			break;
		case MODATTR_ACTIVE_CHECKS_ENABLED:
			payload_new_string(ret, "attr", "active_checks_enabled");
			if(svc)
				payload_new_boolean(ret, "checks_enabled",
					svc->checks_enabled);
			else if(hst)
				payload_new_boolean(ret, "checks_enabled",
					hst->checks_enabled);
			break;
		case MODATTR_PASSIVE_CHECKS_ENABLED:
			payload_new_string(ret, "attr", "passive_checks_enabled");
			if(svc)
				payload_new_boolean(ret, "accept_passive_service_checks",
					svc->accept_passive_service_checks);
			else if(hst)
				payload_new_boolean(ret, "accept_passive_host_checks",
					hst->accept_passive_host_checks);
			break;
		case MODATTR_EVENT_HANDLER_ENABLED:
			payload_new_string(ret, "attr", "event_handler_enabled");
			if(svc)
				payload_new_boolean(ret, "event_handler_enabled",
					svc->event_handler_enabled);
			else if(hst)
				payload_new_boolean(ret, "event_handler_enabled",
					hst->event_handler_enabled);
			break;
		case MODATTR_FLAP_DETECTION_ENABLED:
			payload_new_string(ret, "attr", "flap_detection_enabled");
			if(svc)
				payload_new_boolean(ret, "flap_detection_enabled",
					svc->flap_detection_enabled);
			else if(hst)
				payload_new_boolean(ret, "flap_detection_enabled",
					hst->flap_detection_enabled);
			break;
		case MODATTR_OBSESSIVE_HANDLER_ENABLED:
			payload_new_string(ret, "attr", "obsessive_handler_enabled");
			if(svc)
				payload_new_boolean(ret, "obsess_over_service",
					svc->obsess_over_service);
			else if(hst)
				payload_new_boolean(ret, "obsess_over_host",
					hst->obsess_over_host);
			break;
		case MODATTR_EVENT_HANDLER_COMMAND:
			payload_new_string(ret, "attr", "event_handler_command");
			break;
		case MODATTR_CHECK_COMMAND:
			payload_new_string(ret, "attr", "check_command");
			break;
		case MODATTR_NORMAL_CHECK_INTERVAL:
			payload_new_string(ret, "attr", "normal_check_interval");
			break;
		case MODATTR_RETRY_CHECK_INTERVAL:
			payload_new_string(ret, "attr", "retry_check_interval");
			break;
		case MODATTR_MAX_CHECK_ATTEMPTS:
			payload_new_string(ret, "attr", "max_check_attempts");
			break;
			break;
		case MODATTR_CHECK_TIMEPERIOD:
			payload_new_string(ret, "attr", "check_timeperiod");
			break;
	}

	return ret;
}

void free_cb(void * ptr, void * hint) {
	free(ptr);
}

static int safe_msg_send(zmq_msg_t * msg, void * sock, int flags) {
	int rc;
	do {
		if((rc = zmq_msg_send(msg, sock, flags)) == -1 && errno != EINTR) {
			syslog(LOG_ERR, "Error publishing event: %s", zmq_strerror(errno));
			return -1;
		}
	} while(rc != 0);
	return 0;
}

void process_payload(struct payload * payload) {
	zmq_msg_t type, dump;
	int rc;
	char * header;
	size_t headerlen = strlen(payload->type);

	if(payload->service_description) {
		header = malloc(headerlen + 
			strlen(payload->service_description) +
			strlen(payload->host_name) + sizeof("  "));
		headerlen = sprintf(header, "%s %s %s", payload->type,
			payload->host_name, payload->service_description);
		free(payload->host_name);
		free(payload->service_description);
		free(payload->type);
	} else if(payload->host_name) {
		header = malloc(headerlen + 
			strlen(payload->host_name) + sizeof(" "));
		headerlen = sprintf(header, "%s %s", payload->type,
			payload->host_name);
		free(payload->host_name);
		free(payload->type);
	} else
		header = payload->type;

	zmq_msg_init_data(&type, header, headerlen, free_cb, NULL);
	rc = safe_msg_send(&type, pubext, ZMQ_SNDMORE);
	zmq_msg_close(&type);
	if(rc == -1) {
		free(payload->json_buf);
		free(payload);
		return;
	}

	zmq_msg_init_data(&dump, payload->json_buf, payload->bufused, 
		free_cb, NULL);
	safe_msg_send(&dump, pubext, 0);
	zmq_msg_close(&dump);
	free(payload);
}

int handle_nagdata(int which, void * obj) {
	struct payload * payload = NULL;	
	nebstruct_process_data * raw = obj;
	int rc = 0;

	switch(which) {
	case NEBCALLBACK_EVENT_HANDLER_DATA:
		payload = parse_event_handler(obj);
		if(raw->type == NEBTYPE_EVENTHANDLER_START &&
			overrides[OR_EVENTHANDLER_START])
			rc = NEBERROR_CALLBACKOVERRIDE;
		break;
	case NEBCALLBACK_HOST_CHECK_DATA:
		switch(raw->type) {
			case NEBTYPE_HOSTCHECK_INITIATE:
			case NEBTYPE_HOSTCHECK_PROCESSED:
				payload = parse_host_check(obj);
				if(raw->type == NEBTYPE_HOSTCHECK_INITIATE &&
					overrides[OR_HOSTCHECK_INITIATE])
					rc = NEBERROR_CALLBACKOVERRIDE;
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
				if(raw->type == NEBTYPE_SERVICECHECK_INITIATE &&
					overrides[OR_SERVICECHECK_INITIATE])
					rc = NEBERROR_CALLBACKOVERRIDE;
				break;
			default:
				return 0;
		}
		break;
	case NEBCALLBACK_NOTIFICATION_DATA:
		if(raw->type != NEBTYPE_NOTIFICATION_START)
			return 0;
		payload = parse_notification(obj);
		if(raw->type == NEBTYPE_NOTIFICATION_START &&
			overrides[OR_NOTIFICATION_START])
			rc = NEBERROR_CALLBACKOVERRIDE;
		break;
	case NEBCALLBACK_ACKNOWLEDGEMENT_DATA:
		if(raw->type != NEBTYPE_ACKNOWLEDGEMENT_ADD)
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
	case NEBCALLBACK_ADAPTIVE_HOST_DATA:
	case NEBCALLBACK_ADAPTIVE_SERVICE_DATA:
		payload = parse_adaptivechange(obj);
		break;
	}

	payload_new_timestamp(payload, "timestamp", &raw->timestamp);
	payload_finalize(payload);
	process_payload(payload);
	return rc;
}

static void override_string(const char * in) {
	if(strcasecmp(in, "service_check_initiate") == 0)
		overrides[OR_SERVICECHECK_INITIATE] = 1;
	else if(strcasecmp(in, "host_check_initiate") == 0)
		overrides[OR_HOSTCHECK_INITIATE] = 1;
	else if(strcasecmp(in, "eventhandler_start") == 0)
		overrides[OR_EVENTHANDLER_START] = 1;
	else if(strcasecmp(in, "notification_start") == 0)
		overrides[OR_NOTIFICATION_START] = 1;	
}

int handle_pubstartup(json_t * def) {
	pubext = getsock("publish", ZMQ_PUB, def);
	if(pubext == NULL)
		return -1;

	json_t * override = NULL;
	double sleeptime = 0.0;

	if(get_values(def,
		"override", JSON_ARRAY, 0, &override,
		"startupdelay", JSON_REAL, 0, &sleeptime,
		NULL) != 0) {
		syslog(LOG_ERR, "Parameter error during publisher startup");
		return -1;
	}

	memset(overrides, 0, sizeof(overrides));
	if(override) {
		int i;
		for(i = 0; i < json_array_size(override); i++) {
			json_t * val = json_array_get(override, i);
			if(json_is_string(val))
				override_string(json_string_value(val));
		}
	}

	neb_register_callback(NEBCALLBACK_COMMENT_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_DOWNTIME_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_PROGRAM_STATUS_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_EVENT_HANDLER_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_HOST_CHECK_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_SERVICE_CHECK_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_ACKNOWLEDGEMENT_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_STATE_CHANGE_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_NOTIFICATION_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_ADAPTIVE_HOST_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_ADAPTIVE_SERVICE_DATA, handle,
		0, handle_nagdata);

	if(sleeptime > 0) {
		double integral;
		struct timespec realsleeptime;
		double fractional = modf(sleeptime, &integral);
		realsleeptime.tv_sec = integral;
		realsleeptime.tv_nsec = fractional * 100000000;
		nanosleep(&realsleeptime, NULL);
	}
	return 0;
}

