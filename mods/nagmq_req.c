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
#include "naginclude/skiplist.h"
#include <zmq.h>
#include <pthread.h>
#include "json.h"
#include "jansson.h"

extern int errno;

void lock_obj(char * hostname, char * service, char ** plugin_output,
	char ** long_plugin_output, char ** perf_data);
void unlock_obj(char * hostname, char * service, char * plugin_output,
	char * long_plugin_output, char * perf_data);

static void parse_service(service * state, struct payload * ret,
	int include_host, int include_contacts);
static void parse_host(host * state, struct payload * ret,
	int include_services, int include_contacts);
static void parse_contact(contact * state, struct payload * ret);
static void parse_contactgroup(contactgroup * state, struct payload * ret,
	int include_contacts);

static void parse_custom_variables(struct payload * ret,
	customvariablesmember * cvl) {
	if(cvl && payload_start_object(ret, "custom_variables")) {
		while(cvl) {
			payload_new_string(ret, cvl->variable_name, cvl->variable_value);
			cvl = cvl->next;
		}
		payload_end_object(ret);
	} else if(cvl)
		payload_new_string(ret, "custom_variables", NULL);
}

static void parse_host(host * state, struct payload * ret,
	int include_services, int include_contacts) {
	int rc;

	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "host");
	payload_new_string(ret, "host_name", state->name);
	payload_new_string(ret, "display_name", state->display_name);
	payload_new_string(ret, "alias", state->alias);
	payload_new_string(ret, "address", state->address);

	servicesmember * slck = state->services;
	if(slck && (rc = payload_start_array(ret, "services"))) {
		while(slck) {
			payload_new_string(ret, NULL, slck->service_ptr->description);
			slck = slck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "services", NULL);
	hostsmember *hlck = state->parent_hosts;
	if(hlck && (rc = payload_start_array(ret, "parent_hosts"))) {
		while(hlck) {
			payload_new_string(ret, NULL, hlck->host_name);
			hlck = hlck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "parent_hosts", NULL);

	hlck = state->child_hosts;
	if(hlck && (rc = payload_start_array(ret, "child_hosts"))) {
		while(hlck) {
			payload_new_string(ret, NULL, hlck->host_name);
			hlck = hlck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "child_hosts", NULL);

	contactsmember * clck = state->contacts;
	if(clck && (rc = payload_start_array(ret, "contacts"))) {
		while(clck) {
			payload_new_string(ret, NULL, clck->contact_name);
			clck = clck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "contacts", NULL);

	contactgroupsmember * cglck = state->contact_groups;
	if(cglck && (rc = payload_start_array(ret, "contact_groups"))) {
		while(cglck) {
			payload_new_string(ret, NULL, cglck->group_name);
			cglck = cglck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "contact_groups", NULL);

	payload_new_string(ret, "check_command", state->host_check_command);
	payload_new_integer(ret, "initial_state", state->initial_state);
	payload_new_double(ret, "check_interval", state->check_interval);
	payload_new_double(ret, "retry_interval", state->retry_interval);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_string(ret, "event_handler", state->event_handler);
	payload_new_double(ret, "notification_interval", state->notification_interval);
	payload_new_double(ret, "first_notification_delay", state->first_notification_delay);
	payload_new_boolean(ret, "notify_on_down", state->notify_on_down);
	payload_new_boolean(ret, "notify_on_unreachable", state->notify_on_unreachable);
	payload_new_boolean(ret, "notify_on_recovery", state->notify_on_recovery);
	payload_new_boolean(ret, "notify_on_flapping", state->notify_on_flapping);
	payload_new_boolean(ret, "notify_on_downtime", state->notify_on_downtime);
	payload_new_string(ret, "notification_period", state->notification_period);
	payload_new_string(ret, "check_period", state->check_period);
	payload_new_boolean(ret, "flap_detection_enabled", state->flap_detection_enabled);
	payload_new_double(ret, "low_flap_threshold", state->low_flap_threshold);
	payload_new_double(ret, "high_flap_threshold", state->high_flap_threshold);
	payload_new_boolean(ret, "flap_detection_on_up", state->flap_detection_on_up);
	payload_new_boolean(ret, "flap_detection_on_down", state->flap_detection_on_down);
	payload_new_boolean(ret, "flap_detection_on_unreachable", state->flap_detection_on_unreachable);
	payload_new_boolean(ret, "stalk_on_up", state->stalk_on_up);
	payload_new_boolean(ret, "stalk_on_down", state->stalk_on_down);
	payload_new_boolean(ret, "stalk_on_unreachable", state->stalk_on_unreachable);
	payload_new_boolean(ret, "check_freshness", state->check_freshness);
	payload_new_integer(ret, "freshness_threshold", state->freshness_threshold);
	payload_new_boolean(ret, "process_performance_data", state->process_performance_data);
	payload_new_boolean(ret, "checks_enabled", state->checks_enabled);
	payload_new_boolean(ret, "accept_passive_host_checks", state->accept_passive_host_checks);
	payload_new_boolean(ret, "event_handler_enabled", state->event_handler_enabled);
	payload_new_boolean(ret, "failure_prediction_enabled", state->failure_prediction_enabled);
	payload_new_string(ret, "failure_prediction_options", state->failure_prediction_options);
	payload_new_boolean(ret, "obsess_over_host", state->obsess_over_host);
	payload_new_string(ret, "notes", state->notes);
	payload_new_string(ret, "notes_url", state->notes_url);
	payload_new_string(ret, "action_url", state->action_url);
	payload_new_string(ret, "icon_image", state->icon_image);
	payload_new_string(ret, "icon_image_alt", state->icon_image_alt);
	payload_new_string(ret, "vrml_image", state->vrml_image);
	payload_new_string(ret, "statusmap_image", state->statusmap_image);
	payload_new_integer(ret, "have_2d_coords", state->have_2d_coords);
	payload_new_integer(ret, "x_2d", state->x_2d);
	payload_new_integer(ret, "y_2d", state->y_2d);
	payload_new_integer(ret, "have_3d_coords", state->have_3d_coords);
	payload_new_double(ret, "x_3d", state->x_3d);
	payload_new_double(ret, "y_3d", state->y_3d);
	payload_new_double(ret, "z_3d", state->z_3d);
	payload_new_integer(ret, "should_be_drawn", state->should_be_drawn);
	payload_new_boolean(ret, "retain_status_information", state->retain_status_information);
	payload_new_boolean(ret, "retain_nonstatus_information", state->retain_nonstatus_information);
	payload_new_integer(ret, "modified_attributes", state->modified_attributes);
	payload_new_integer(ret, "circular_path_checked", state->circular_path_checked);
	payload_new_integer(ret, "contains_circular_path", state->contains_circular_path);
	payload_new_integer(ret, "problem_has_been_acknowledged", state->problem_has_been_acknowledged);
	payload_new_integer(ret, "current_state", state->current_state);
	payload_new_integer(ret, "last_state", state->last_state);
	payload_new_integer(ret, "last_hard_state", state->last_hard_state);

	if(payload_has_keys(ret, "plugin_output",
		"long_plugin_output", "perf_data", NULL) > 0) {
		char * plugin_output, *long_plugin_output, *perf_data;
		lock_obj(state->name, NULL, &plugin_output,
			&long_plugin_output, &perf_data);
		payload_new_string(ret, "plugin_output", plugin_output);
		payload_new_string(ret, "long_plugin_output", long_plugin_output);
		payload_new_string(ret, "perf_data", perf_data);
		unlock_obj(state->name, NULL, NULL, NULL, NULL);
	}
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "current_event_id", state->current_event_id);
	payload_new_integer(ret, "last_event_id", state->last_event_id);
	payload_new_integer(ret, "current_problem_id", state->current_problem_id);
	payload_new_integer(ret, "last_problem_id", state->last_problem_id);
	payload_new_double(ret, "latency", state->latency);
	payload_new_double(ret, "execution_time", state->execution_time);
	payload_new_boolean(ret, "is_executing", state->is_executing);
	payload_new_integer(ret, "check_options", state->check_options);
	payload_new_boolean(ret, "notifications_enabled", state->notifications_enabled);
	payload_new_integer(ret, "last_host_notification", state->last_host_notification);
	payload_new_integer(ret, "next_host_notification", state->next_host_notification);
	payload_new_integer(ret, "next_check", state->next_check);
	payload_new_boolean(ret, "should_be_scheduled", state->should_be_scheduled);
	payload_new_integer(ret, "last_check", state->last_check);
	payload_new_integer(ret, "last_state_change", state->last_state_change);
	payload_new_integer(ret, "last_hard_state_change", state->last_hard_state_change);
	payload_new_integer(ret, "last_time_up", state->last_time_up);
	payload_new_integer(ret, "last_time_down", state->last_time_down);
	payload_new_integer(ret, "last_time_unreachable", state->last_time_unreachable);
	payload_new_boolean(ret, "has_been_checked", state->has_been_checked);
	payload_new_boolean(ret, "is_being_freshened", state->is_being_freshened);
	payload_new_boolean(ret, "notified_on_down", state->notified_on_down);
	payload_new_boolean(ret, "notified_on_unreachable", state->notified_on_unreachable);
	payload_new_integer(ret, "current_notification_number", state->current_notification_number);
	payload_new_boolean(ret, "no_more_notifications", state->no_more_notifications);
	payload_new_integer(ret, "current_notification_id", state->current_notification_id);
	payload_new_boolean(ret, "check_flapping_recovery_notification", state->check_flapping_recovery_notification);
	payload_new_integer(ret, "scheduled_downtime_depth", state->scheduled_downtime_depth);
	payload_new_integer(ret, "pending_flex_downtime", state->pending_flex_downtime);
	if(payload_start_array(ret, "state_history")) {
		int i;
		for(i = 0; i < state->state_history_index; i++) {
			payload_new_integer(ret, NULL, state->state_history[i]);
		}
		payload_end_array(ret);
	}
	payload_new_integer(ret, "last_state_history_update", state->last_state_history_update);
	payload_new_boolean(ret, "is_flapping", state->is_flapping);
	payload_new_integer(ret, "flapping_comment_id", state->flapping_comment_id);
	payload_new_double(ret, "percent_state_change", state->percent_state_change);
	payload_new_integer(ret, "total_service_check_interval", state->total_service_check_interval);
	parse_custom_variables(ret, state->custom_variables);
	payload_end_object(ret);

	if(include_services) {
		slck = state->services;
		while(slck) {
			parse_service(slck->service_ptr, ret, 0, 0);
			slck = slck->next;
		}
	}

	if(include_contacts) {
		clck = state->contacts;
		while(clck) {
			parse_contact(clck->contact_ptr, ret);
			clck = clck->next;
		}

		cglck = state->contact_groups;
		while(cglck) {
			parse_contactgroup(cglck->group_ptr, ret, include_contacts);
			cglck = cglck->next;
		}
	}
}

static void parse_service(service * state, struct payload * ret,
	int include_host, int include_contacts) {
	int rc;
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "service");
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->description);
	payload_new_string(ret, "display_name", state->display_name);
	payload_new_string(ret, "check_command", state->service_check_command);
	payload_new_string(ret, "event_handler", state->event_handler);
	payload_new_integer(ret, "initial_state", state->initial_state);
	payload_new_double(ret, "check_interval", state->check_interval);
	payload_new_double(ret, "retry_interval", state->retry_interval);
	payload_new_integer(ret, "max_attempts", state->max_attempts);
	payload_new_integer(ret, "parallelize", state->parallelize);
	contactsmember * clck = state->contacts;
	if(clck && (rc = payload_start_array(ret, "contacts"))) {
		while(clck) {
			payload_new_string(ret, NULL, clck->contact_name);
			clck = clck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "contacts", NULL);

	contactgroupsmember * cglck = state->contact_groups;
	if(cglck && (rc = payload_start_array(ret, "contact_groups"))) {
		while(cglck) {
			payload_new_string(ret, NULL, cglck->group_name);
			cglck = cglck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "contact_groups", NULL);

	payload_new_double(ret, "notification_interval", state->notification_interval);
	payload_new_double(ret, "first_notification_delay", state->first_notification_delay);
	payload_new_boolean(ret, "notify_on_unknown", state->notify_on_unknown);
	payload_new_boolean(ret, "notify_on_warning", state->notify_on_warning);
	payload_new_boolean(ret, "notify_on_critical", state->notify_on_critical);
	payload_new_boolean(ret, "notify_on_recovery", state->notify_on_recovery);
	payload_new_boolean(ret, "notify_on_flapping", state->notify_on_flapping);
	payload_new_boolean(ret, "notify_on_downtime", state->notify_on_downtime);
	payload_new_boolean(ret, "stalk_on_ok", state->stalk_on_ok);
	payload_new_boolean(ret, "stalk_on_warning", state->stalk_on_warning);
	payload_new_boolean(ret, "stalk_on_unknown", state->stalk_on_unknown);
	payload_new_boolean(ret, "stalk_on_critical", state->stalk_on_critical);
	payload_new_boolean(ret, "is_volatile", state->is_volatile);
	payload_new_string(ret, "notification_period", state->notification_period);
	payload_new_string(ret, "check_period", state->check_period);
	payload_new_boolean(ret, "flap_detection_enabled", state->flap_detection_enabled);
	payload_new_double(ret, "low_flap_threshold", state->low_flap_threshold);
	payload_new_double(ret, "high_flap_threshold", state->high_flap_threshold);
	payload_new_boolean(ret, "flap_detection_on_ok", state->flap_detection_on_ok);
	payload_new_boolean(ret, "flap_detection_on_warning", state->flap_detection_on_warning);
	payload_new_boolean(ret, "flap_detection_on_unknown", state->flap_detection_on_unknown);
	payload_new_boolean(ret, "flap_detection_on_critical", state->flap_detection_on_critical);
	payload_new_boolean(ret, "process_performance_data", state->process_performance_data);
	payload_new_integer(ret, "check_freshness", state->check_freshness);
	payload_new_integer(ret, "freshness_threshold", state->freshness_threshold);
	payload_new_boolean(ret, "accept_passive_service_checks", state->accept_passive_service_checks);
	payload_new_boolean(ret, "event_handler_enabled", state->event_handler_enabled);
	payload_new_boolean(ret, "checks_enabled", state->checks_enabled);
	payload_new_boolean(ret, "notifications_enabled", state->notifications_enabled);
	payload_new_boolean(ret, "obsess_over_service", state->obsess_over_service);
	payload_new_boolean(ret, "failure_prediction_enabled", state->failure_prediction_enabled);
	payload_new_string(ret, "failure_prediction_options", state->failure_prediction_options);
	payload_new_string(ret, "notes", state->notes);
	payload_new_string(ret, "notes_url", state->notes_url);
	payload_new_string(ret, "action_url", state->action_url);
	payload_new_string(ret, "icon_image", state->icon_image);
	payload_new_string(ret, "icon_image_alt", state->icon_image_alt);
	payload_new_integer(ret, "modified_attributes", state->modified_attributes);
	payload_new_boolean(ret, "retain_status_information", state->retain_status_information);
	payload_new_boolean(ret, "retain_nonstatus_information", state->retain_nonstatus_information);
	payload_new_boolean(ret, "problem_has_been_acknowledged", state->problem_has_been_acknowledged);
	payload_new_integer(ret, "host_problem_at_last_check", state->host_problem_at_last_check);
	payload_new_integer(ret, "current_state", state->current_state);
	payload_new_integer(ret, "last_state", state->last_state);
	payload_new_integer(ret, "last_hard_state", state->last_hard_state);
	if(payload_has_keys(ret, "plugin_output",
		"long_plugin_output", "perf_data", NULL) > 0) {
		char * plugin_output, *long_plugin_output, *perf_data;
		lock_obj(state->host_name, state->description, &plugin_output,
			&long_plugin_output, &perf_data);
		payload_new_string(ret, "plugin_output", plugin_output);
		payload_new_string(ret, "long_plugin_output", long_plugin_output);
		payload_new_string(ret, "perf_data", perf_data);
		unlock_obj(state->host_name, state->description, NULL, NULL, NULL);
	}
	payload_new_integer(ret, "next_check", state->next_check);
	payload_new_boolean(ret, "should_be_scheduled", state->should_be_scheduled);
	payload_new_integer(ret, "last_check", state->last_check);
	payload_new_integer(ret, "current_attempt", state->current_attempt);
	payload_new_integer(ret, "current_event_id", state->current_event_id);
	payload_new_integer(ret, "last_event_id", state->last_event_id);
	payload_new_integer(ret, "current_problem_id", state->current_problem_id);
	payload_new_integer(ret, "last_problem_id", state->last_problem_id);
	payload_new_integer(ret, "last_notification", state->last_notification);
	payload_new_integer(ret, "next_notification", state->next_notification);
	payload_new_boolean(ret, "no_more_notifications", state->no_more_notifications);
	payload_new_integer(ret, "check_flapping_recovery_notification", state->check_flapping_recovery_notification);
	payload_new_integer(ret, "last_state_change", state->last_state_change);
	payload_new_integer(ret, "last_hard_state_change", state->last_hard_state_change);
	payload_new_integer(ret, "last_time_ok", state->last_time_ok);
	payload_new_integer(ret, "last_time_warning", state->last_time_warning);
	payload_new_integer(ret, "last_time_unknown", state->last_time_unknown);
	payload_new_integer(ret, "last_time_critical", state->last_time_critical);
	payload_new_boolean(ret, "has_been_checked", state->has_been_checked);
	payload_new_boolean(ret, "is_being_freshened", state->is_being_freshened);
	payload_new_boolean(ret, "notified_on_unknown", state->notified_on_unknown);
	payload_new_boolean(ret, "notified_on_warning", state->notified_on_warning);
	payload_new_boolean(ret, "notified_on_critical", state->notified_on_critical);
	payload_new_integer(ret, "current_notification_number", state->current_notification_number);
	payload_new_integer(ret, "current_notification_id", state->current_notification_id);
	payload_new_double(ret, "latency", state->latency);
	payload_new_double(ret, "execution_time", state->execution_time);
	payload_new_boolean(ret, "is_executing", state->is_executing);
	payload_new_integer(ret, "check_options", state->check_options);
	payload_new_integer(ret, "scheduled_downtime_depth", state->scheduled_downtime_depth);
	payload_new_boolean(ret, "pending_flex_downtime", state->pending_flex_downtime);
	if(payload_start_array(ret, "state_history")) {
		int i;
		for(i = 0; i < state->state_history_index; i++)
			payload_new_integer(ret, NULL, state->state_history[i]);
		payload_end_array(ret);
	}
	payload_new_boolean(ret, "is_flapping", state->is_flapping);
	payload_new_integer(ret, "flapping_comment_id", state->flapping_comment_id);
	payload_new_double(ret, "percent_state_change", state->percent_state_change);
	parse_custom_variables(ret, state->custom_variables);
	payload_end_object(ret);

	if(include_host)
		parse_host(state->host_ptr, ret, 0, 0);

	if(include_contacts) {
		clck = state->contacts;
		while(clck) {
			parse_contact(clck->contact_ptr, ret);
			clck = clck->next;
		}

		cglck = state->contact_groups;
		while(cglck) {
			parse_contactgroup(cglck->group_ptr, ret, include_contacts);
			cglck = cglck->next;
		}
	}
}


static void parse_hostgroup(hostgroup * state, struct payload * ret,
	int include_hosts) {
	int rc;
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "hostgroup");
	payload_new_string(ret, "group_name", state->group_name);
	payload_new_string(ret, "alias", state->alias);
	payload_new_string(ret, "notes", state->notes);
	payload_new_string(ret, "notes_url", state->notes_url);
	payload_new_string(ret, "action_url", state->action_url);
	hostsmember *hlck = state->members;
	if(hlck && (rc = payload_start_array(ret, "members"))) {
		while(hlck) {
			payload_new_string(ret, NULL, hlck->host_name);
			hlck = hlck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "members", NULL);
	payload_end_object(ret);
	if(include_hosts) {
		hostsmember * htmp = state->members;
		while(htmp) {
			parse_host(htmp->host_ptr, ret, 0, 0);
			htmp = htmp->next;
		}
	}
}

static void parse_servicegroup(servicegroup * state, struct payload * ret,
	int include_services) {
	int rc;
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "servicegroup");
	payload_new_string(ret, "group_name", state->group_name);
	payload_new_string(ret, "alias", state->alias);
	payload_new_string(ret, "notes", state->notes);
	payload_new_string(ret, "notes_url", state->notes_url);
	payload_new_string(ret, "action_url", state->action_url);
	servicesmember *slck = state->members;
	if(slck && (rc = payload_start_array(ret, "members"))) {
		while(slck) {
			payload_new_string(ret, NULL, slck->service_description);
			slck = slck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "members", NULL);
	payload_end_object(ret);
	if(include_services) {
		servicesmember * stmp = state->members;
		while(stmp) {
			parse_service(stmp->service_ptr, ret, 0, 0);
			stmp = stmp->next;
		}
	}
}

static void parse_contact(contact * state, struct payload * ret) {
	payload_start_object(ret, NULL);
	int rc;
	payload_new_string(ret, "type", "contact");
	payload_new_string(ret, "name", state->name);
	payload_new_string(ret, "alias", state->alias);
	payload_new_string(ret, "email", state->email);
	payload_new_string(ret, "pager", state->pager);
	if(state->address[0] && (rc = payload_start_array(ret, "address"))) {
		int i;
		for(i = 0; i < MAX_CONTACT_ADDRESSES; i++)
			payload_new_string(ret, NULL, state->address[i]);
		payload_end_array(ret);
	} else
		payload_new_string(ret, "address", NULL);
	payload_new_boolean(ret, "notify_on_service_unknown", state->notify_on_service_unknown);
	payload_new_boolean(ret, "notify_on_service_warning", state->notify_on_service_warning);
	payload_new_boolean(ret, "notify_on_service_critical", state->notify_on_service_critical);
	payload_new_boolean(ret, "notify_on_service_recovery", state->notify_on_service_recovery);
	payload_new_boolean(ret, "notify_on_service_flapping", state->notify_on_service_flapping);
	payload_new_boolean(ret, "notify_on_service_downtime", state->notify_on_service_downtime);
	payload_new_boolean(ret, "notify_on_host_down", state->notify_on_host_down);
	payload_new_boolean(ret, "notify_on_host_unreachable", state->notify_on_host_unreachable);
	payload_new_boolean(ret, "notify_on_host_recovery", state->notify_on_host_recovery);
	payload_new_boolean(ret, "notify_on_host_flapping", state->notify_on_host_flapping);
	payload_new_boolean(ret, "notify_on_host_downtime", state->notify_on_host_downtime);
	payload_new_string(ret, "host_notification_period", state->host_notification_period);
	payload_new_string(ret, "service_notification_period", state->service_notification_period);
	payload_new_boolean(ret, "host_notifications_enabled", state->host_notifications_enabled);
	payload_new_boolean(ret, "service_notifications_enabled", state->service_notifications_enabled);
	payload_new_boolean(ret, "can_submit_commands", state->can_submit_commands);
	payload_new_boolean(ret, "retain_status_information", state->retain_status_information);
	payload_new_boolean(ret, "retain_nonstatus_information", state->retain_nonstatus_information);
	payload_new_integer(ret, "last_host_notification", state->last_host_notification);
	payload_new_integer(ret, "last_service_notification", state->last_service_notification);
	payload_new_integer(ret, "modified_attributes", state->modified_attributes);
	payload_new_integer(ret, "modified_host_attributes", state->modified_host_attributes);
	payload_new_integer(ret, "modified_service_attributes", state->modified_service_attributes);
	parse_custom_variables(ret, state->custom_variables);
	payload_end_object(ret);
}

extern host * host_list;
extern service * service_list;

static void parse_contactgroup(contactgroup * state, struct payload * ret,
	int include_contacts) {
	int rc;
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "contactgroup");
	payload_new_string(ret, "group_name", state->group_name);
	payload_new_string(ret, "alias", state->alias);
	contactsmember * clck = state->members;
	if(clck && (rc = payload_start_array(ret, "members"))) {
		while(clck) {
			payload_new_string(ret, NULL, clck->contact_name);
			clck = clck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "members", NULL);
	payload_end_object(ret);

	if(include_contacts) {
		contactsmember * ctmp = state->members;
		while(ctmp) {
			parse_contact(ctmp->contact_ptr, ret);
			ctmp = ctmp->next;
		}
	}
}

void free_cb(void * ptr, void * hint);

void send_msg(void * sock, struct payload * po) {
	payload_finalize(po);
	zmq_msg_t outmsg;
	zmq_msg_init_data(&outmsg, po->json_buf, po->bufused, free_cb, NULL);
	zmq_send(sock, &outmsg, 0);
	zmq_msg_close(&outmsg);
	free(po->type);
	free(po);
}

void do_list_hosts(struct payload * po, int expand_lists,
	int include_services, int include_contacts) {
	if(!expand_lists) {
		payload_start_object(po, NULL);
		payload_new_string(po, "type", "host_list");
		payload_start_array(po, "hosts");
	}
	host * tmp_host = host_list;
	while(tmp_host) {
		if(expand_lists)
			parse_host(tmp_host, po, include_services, include_contacts);
		else
			payload_new_string(po, NULL, tmp_host->name);
		tmp_host = tmp_host->next;
	}
	if(!expand_lists) {
		payload_end_array(po);
		payload_end_object(po);
	}
}

void do_list_services(struct payload * po, int expand_lists,
	int include_hosts, int include_contacts, const char * tolist) {
	if(!expand_lists) {
		payload_start_object(po, NULL);
		payload_new_string(po, "type", "service_list");
		payload_start_array(po, "services");
	}
	service * tmp_svc = service_list;
	while(tmp_svc) {
		if(tolist && strcmp(tolist, tmp_svc->description) != 0) {
			tmp_svc = tmp_svc->next;
			continue;
		}
		if(expand_lists)
			parse_service(tmp_svc, po, include_hosts, include_contacts);
		else {
			payload_start_object(po, NULL);
			payload_new_string(po, "host_name", tmp_svc->host_ptr->name);
			payload_new_string(po, "service_description", tmp_svc->description);
			payload_end_object(po);
		}
		tmp_svc = tmp_svc->next;
	}
	if(!expand_lists) {
		payload_end_array(po);
		payload_end_object(po);
	}
}

void err_msg(struct payload * po, char * msg, ...) {
	payload_start_object(po, NULL);
	payload_new_string(po, "type", "error");
	if(po->keys)
		payload_hash_key(po, "msg");
	payload_new_string(po, "msg", msg);
	va_list ap;
	
	char * key, *val;
	va_start(ap, msg);
	while((key = va_arg(ap, char*)) != NULL &&
		(val = va_arg(ap, char*)) != NULL) {
		payload_new_string(po, key, val);
	}
	payload_end_object(po);
}

void process_req_msg(void * sock) {
	zmq_msg_t reqmsg;
	json_t * req;
	char * host_name = NULL, *service_description = NULL;
	char * hostgroup_name = NULL, *servicegroup_name = NULL;
	char * contact_name = NULL, *contactgroup_name = NULL;
	int include_services = 0, include_hosts = 0, include_contacts = 0;
	int list_hosts = 0, expand_lists = 0;
	json_t * list_services = NULL, *keys = NULL;
	struct payload * po;

	zmq_msg_init(&reqmsg);
	if(zmq_recv(sock, &reqmsg, 0) != 0)
		return;

	req = json_loadb(zmq_msg_data(&reqmsg), zmq_msg_size(&reqmsg), 0, NULL);
	zmq_msg_close(&reqmsg);
	if(req == NULL)
		return;

	if(json_unpack(req, "{ s?:s s?:s s?:s s?:s s?:s s?:s s?:b s?:b"
		" s?:b s?:b s?:o s?:b s?:o }",
		"host_name", &host_name, "service_description",
		&service_description, "hostgroup_name", &hostgroup_name,
		"servicegroup_name", &servicegroup_name,
		"contact_name", &contact_name, "contactgroup_name",
		&contactgroup_name, "include_services", &include_services,
		"include_hosts", &include_hosts, "include_contacts",
		&include_contacts, "list_hosts", &list_hosts, 
		"list_services", &list_services,
		"expand_lists", &expand_lists, "keys", &keys) != 0) {
		json_decref(req);
		return;
	}

	po = malloc(sizeof(struct payload));
	memset(po, 0, sizeof(struct payload));
	payload_start_array(po, NULL);

	if(keys != NULL && json_is_array(keys)) {
		int i;
		for(i = 0; i < json_array_size(keys); i++) {
			json_t * keytmp = json_array_get(keys, i);
			if(!json_is_string(keytmp))
				continue;
			payload_hash_key(po, json_string_value(keytmp));
		}
	}

	if(list_hosts)
		do_list_hosts(po, expand_lists, include_services, include_contacts);

	if(json_is_string(list_services) || json_is_true(list_services))
		do_list_services(po, expand_lists, include_hosts, include_contacts,
			json_is_string(list_services) ?
			json_string_value(list_services) : NULL);

	if(service_description) {
		service * svctarget;
		if(!host_name) {
			err_msg(po, "No host specified for service", "service_description",
				service_description, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}

		svctarget = find_service(host_name, service_description);
		if(!svctarget) {
			err_msg(po, "Could not find service", "service_description",
				service_description, "host_name", host_name, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}
		
		parse_service(svctarget, po, include_hosts, include_contacts);
	} else if(host_name) {
		host * hsttarget = find_host(host_name);
		if(!hsttarget) {
			err_msg(po, "Could not find host", "host_name", host_name, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}
		parse_host(hsttarget, po, include_services, include_contacts);
	}
	if(hostgroup_name) {
		hostgroup * hsttarget = find_hostgroup(hostgroup_name);
		if(hsttarget == NULL) {
			err_msg(po, "Could not find hostgroup", "hostgroup_name",
				hostgroup_name, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}
		parse_hostgroup(hsttarget, po, include_hosts);
	}
	if(servicegroup_name) {
		servicegroup * svctarget = find_servicegroup(servicegroup_name);
		if(svctarget == NULL) {
			err_msg(po, "Could not find servicegroup", "servicegroup_name",
				servicegroup_name, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}
		parse_servicegroup(svctarget, po, include_services);
	}
	if(contactgroup_name) {
		contactgroup * cntarget = find_contactgroup(contactgroup_name);
		if(cntarget == NULL) {
			err_msg(po, "Could not find contactgroup", "contactgroup_name",
				contactgroup_name, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}
		parse_contactgroup(cntarget, po, include_contacts);
	}
	if(contact_name) {
		contact * cntarget = find_contact(contact_name);
		if(cntarget == NULL) {
			err_msg(po, "Could not find contact", "contact_name",
				contact_name, NULL);
			send_msg(sock, po);
			json_decref(req);
			return;
		}
		parse_contact(cntarget, po);
	}

	json_decref(req);
	send_msg(sock, po);
}
