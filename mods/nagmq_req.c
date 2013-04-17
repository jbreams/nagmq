#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#define NSCORE 1
#include "nebstructs.h"
#include "nebcallbacks.h"
#include "nebmodules.h"
#include "nebmods.h"
#include "nagios.h"
#include "objects.h"
#include "broker.h"
#include "skiplist.h"
#include "comments.h"
#include "downtime.h"
#include <zmq.h>
#include "json.h"
#include "common.h"

extern int errno;
extern host * host_list;
extern service * service_list;
extern hostgroup * hostgroup_list;
extern servicegroup * servicegroup_list;
extern void * reqsock;

static char * host_name, *service_description;
static int include_services, include_hosts,
	include_contacts, expand_lists;

static contact * for_user = NULL;
static service * cur_service = NULL;
static host * cur_host = NULL;

static void parse_service(service * state, struct payload * ret);
static void parse_host(host * state, struct payload * ret);
static void parse_contact(contact * state, struct payload * ret);
static void parse_contactgroup(contactgroup * state, struct payload * ret);

static void parse_custom_variables(struct payload * ret,
	customvariablesmember * cvl) {
	while(cvl) {
		payload_new_string(ret, cvl->variable_name, cvl->variable_value);
		cvl = cvl->next;
	}
}

// Timeperiod parsing routines adapted from xodtemplate_cache_objects in
// xdata/xodtemplate.c in the nagios source
static char *days[7]={"sunday","monday","tuesday","wednesday","thursday","friday","saturday"};

static void parse_timerange(timerange * tr, struct payload * ret) {
	char buf[16];
	int hours, minutes;

	if(tr->range_start == 0 && tr->range_end == 0)
		return;

	hours = tr->range_start / 3600;
	minutes = tr->range_start - (hours * 3600);
	if(minutes)
		minutes /= 60;
	sprintf(buf, "%02d:%02d", hours, minutes);
	payload_new_string(ret, "start_time", buf);
	hours = tr->range_end / 3600;
	minutes = tr->range_end - (hours * 3600);
	if(minutes)
		minutes /= 60;
	sprintf(buf, "%02d:%02d", hours, minutes);
	payload_new_string(ret, "end_time", buf);
}

static void parse_daterange(daterange * dr, struct payload * ret) {
	char buf[1024];
	const char *months[12]={"january","february","march","april","may","june","july","august","september","october","november","december"};

	if(dr->times == NULL)
		return;

	payload_start_object(ret, NULL);
	switch(dr->type) {
		case DATERANGE_CALENDAR_DATE:
			sprintf(buf, "%d-%02d-%02d",
				dr->syear, dr->smon + 1, dr->smday );
			payload_new_string(ret, "type", "calendar_date");
			payload_new_string(ret, "start", buf);
			if((dr->smday != dr->emday) ||
				(dr->smon != dr->emon) ||
				(dr->syear != dr->eyear)) {
				sprintf(buf, "%d-%02d-%02d", dr->eyear, dr->emon + 1, dr->emday);
				payload_new_string(ret, "end", buf);
				if(dr->skip_interval > 1)
					payload_new_integer(ret, "skip_interval", dr->skip_interval);
			}
			break;
		case DATERANGE_MONTH_DATE:
			payload_new_string(ret, "type", "month_date");
			sprintf(buf, "%s %d", months[dr->smon], dr->smday);
			payload_new_string(ret, "start", buf);
			if(dr->smon != dr->emon ||
				dr->smday != dr->emday) {
				sprintf(buf, "%s %d", months[dr->emon], dr->emday);
				payload_new_string(ret, "end", buf);
				if(dr->skip_interval > 1)
					payload_new_integer(ret, "skip_interval", dr->skip_interval);
			}
			break;
		case DATERANGE_MONTH_DAY:
			payload_new_string(ret, "type", "month_day");
			payload_new_integer(ret, "start", dr->smday);
			
			if(dr->smday != dr->emday) {
				payload_new_integer(ret, "end", dr->emday);
				if(dr->skip_interval > 1)
					payload_new_integer(ret, "skip_interval", dr->skip_interval);
			}
			break;
		case DATERANGE_MONTH_WEEK_DAY:
			payload_new_string(ret, "type", "month_week_day");
			sprintf(buf, "%s %d %s", days[dr->swday],
				dr->swday_offset, months[dr->smon]);
			payload_new_string(ret, "start", buf);
			if((dr->smon != dr->emon) ||
				(dr->swday != dr->ewday) ||
				(dr->swday_offset != dr->ewday_offset)) {
				sprintf(buf, "%s %d %s", days[dr->ewday],
					dr->ewday_offset, months[dr->emon]);
				payload_new_string(ret, "end", buf);
				if(dr->skip_interval > 1)
					payload_new_integer(ret, "skip_interval", dr->skip_interval);
			}
			break;
		case DATERANGE_WEEK_DAY:
			payload_new_string(ret, "type", "week_day");
			sprintf(buf, "%s %d", days[dr->swday], dr->swday_offset);
			payload_new_string(ret, "start", buf);
			if((dr->swday != dr->ewday) ||
				(dr->swday_offset != dr->ewday_offset)) {
				sprintf(buf, "%s %d", days[dr->ewday], dr->ewday_offset);
				payload_new_string(ret, "end", buf);
				if(dr->skip_interval > 1)
					payload_new_integer(ret, "skip_interval", dr->skip_interval);
			}
			break;
	}
	parse_timerange(dr->times, ret);
	payload_end_object(ret);
}

static void parse_timeperiod(timeperiod * state, struct payload * ret) {
	int x;
	time_t now;
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "timeperiod");
	payload_new_string(ret, "timeperiod_name", state->name);
	payload_new_string(ret, "alias", state->alias);
	if(payload_start_array(ret, "exceptions")) {
		for(x = 0; x < DATERANGE_TYPES; x++) {
			daterange * drlck;
			for(drlck = state->exceptions[x]; drlck != NULL;
				drlck = drlck->next)
				parse_daterange(drlck, ret);
		}
		payload_end_array(ret);
	}

	for(x = 0; x < 7; x++) {
		if(state->days[x] == NULL)
			continue;
		if(payload_start_object(ret, days[x])) {
			parse_timerange(state->days[x], ret);
			payload_end_object(ret);
		}
	}

	time(&now);
	payload_new_boolean(ret, "in_timeperiod",
		(check_time_against_period(now, state) == 0));
	get_next_valid_time(now, &now, state);
	payload_new_integer(ret, "next_valid_time", now);
	
	timeperiodexclusion * tpelck = state->exclusions;
	if(tpelck && payload_start_array(ret, "exclusions")) {
		while(tpelck) {
			payload_new_string(ret, NULL, tpelck->timeperiod_name);
			tpelck = tpelck->next;
		}
		payload_end_array(ret);
	} else if(!tpelck)
		payload_new_string(ret, "exclusions", NULL);

	payload_end_object(ret);
}

static void parse_host(host * state, struct payload * ret) {
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
			payload_new_string(ret, NULL, hlck->host_ptr->name);
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

	objectlist * hglck = state->hostgroups_ptr;
	if(hglck && (rc = payload_start_array(ret, "hostgroups"))) {
		while(hglck && hglck->object_ptr) {
			hostgroup * hg = hglck->object_ptr;
			payload_new_string(ret, NULL, hg->group_name);
			hglck = hglck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "hostgroups", NULL);

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
	payload_new_boolean(ret, "problem_has_been_acknowledged", state->problem_has_been_acknowledged);
	payload_new_integer(ret, "current_state", state->current_state);
	payload_new_statestr(ret, "current_state_str", state->current_state, state->has_been_checked, 0);
	payload_new_integer(ret, "last_state", state->last_state);
	payload_new_statestr(ret, "last_state_str", state->current_state, state->has_been_checked, 0);
	payload_new_integer(ret, "last_hard_state", state->last_hard_state);
	payload_new_statestr(ret, "last_hard_state_str", state->last_hard_state, state->has_been_checked, 0);
	payload_new_string(ret, "plugin_output", state->plugin_output);
	payload_new_string(ret, "long_plugin_output", state->long_plugin_output);
	payload_new_string(ret, "perf_data", state->perf_data);
	payload_new_integer(ret, "state_type", state->state_type);
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
	payload_new_integer(ret, "last_notification", state->last_host_notification);
	payload_new_integer(ret, "next_notification", state->next_host_notification);
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
			parse_service(slck->service_ptr, ret);
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
			parse_contactgroup(cglck->group_ptr, ret);
			cglck = cglck->next;
		}
	}
}

static void parse_service(service * state, struct payload * ret) {
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

	objectlist * sgplck = state->servicegroups_ptr;
	if(sgplck && (rc = payload_start_array(ret, "servicegroups"))) {
		while(sgplck && sgplck->object_ptr) {
			servicegroup * sg = sgplck->object_ptr;
			payload_new_string(ret, NULL, sg->group_name);
			sgplck = sgplck->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "servicegroups", NULL);

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
	payload_new_statestr(ret, "current_state_str", state->current_state, state->has_been_checked, 1);
	payload_new_integer(ret, "last_state", state->last_state);
	payload_new_statestr(ret, "last_state_str", state->last_state, state->has_been_checked, 1);
	payload_new_integer(ret, "last_hard_state", state->last_hard_state);
	payload_new_statestr(ret, "last_hard_state_str", state->last_hard_state, state->has_been_checked, 1);
	payload_new_string(ret, "plugin_output", state->plugin_output);
	payload_new_string(ret, "long_plugin_output", state->long_plugin_output);
	payload_new_string(ret, "perf_data", state->perf_data);
	payload_new_integer(ret, "state_type", state->state_type);
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

	if(include_hosts)
		parse_host(state->host_ptr, ret);

	if(include_contacts) {
		clck = state->contacts;
		while(clck) {
			parse_contact(clck->contact_ptr, ret);
			clck = clck->next;
		}

		cglck = state->contact_groups;
		while(cglck) {
			parse_contactgroup(cglck->group_ptr, ret);
			cglck = cglck->next;
		}
	}
}

static void parse_hostgroup(hostgroup * state, struct payload * ret) {
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
			if(for_user && !is_contact_for_host(hlck->host_ptr, for_user)) {
				hlck = hlck->next;
				continue;
			}
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
			if(for_user && !is_contact_for_host(htmp->host_ptr, for_user)) {
				htmp = htmp->next;
				continue;
			}
			parse_host(htmp->host_ptr, ret);
			htmp = htmp->next;
		}
	}
}

static void parse_servicegroup(servicegroup * state, struct payload * ret) {
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
			if(for_user && !is_contact_for_service(slck->service_ptr, for_user)) {
				slck = slck->next;
				continue;
			}
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
			if(for_user && !is_contact_for_service(stmp->service_ptr, for_user)) {
				stmp = stmp->next;
				continue;
			}
			parse_service(stmp->service_ptr, ret);
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
	if(state->contactgroups_ptr && (rc = payload_start_array(ret, "contact_groups"))) {
		objectlist * link = state->contactgroups_ptr;
		while(link) {
			payload_new_string(ret, NULL,
				((contactgroup*)link->object_ptr)->group_name);
			link = link->next;
		}
		payload_end_array(ret);
	} else
		payload_new_string(ret, "contactgroups", NULL);
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

	if(payload_start_array(ret, "host_notification_options")) {
		if(state->notify_on_host_down)
			payload_new_string(ret, NULL, "d");
		if(state->notify_on_host_unreachable)
			payload_new_string(ret, NULL, "u");
		if(state->notify_on_host_recovery)
			payload_new_string(ret, NULL, "r");
		if(state->notify_on_host_flapping)
			payload_new_string(ret, NULL, "f");
		if(state->notify_on_host_downtime)
			payload_new_string(ret, NULL, "s");
		payload_end_array(ret);
	}

	if(payload_start_array(ret, "service_notification_options")) {
		if(state->notify_on_service_unknown)
			payload_new_string(ret, NULL, "u");
		if(state->notify_on_service_warning)
			payload_new_string(ret, NULL, "w");
		if(state->notify_on_service_critical)
			payload_new_string(ret, NULL, "c");
		if(state->notify_on_service_recovery)
			payload_new_string(ret, NULL, "r");
		if(state->notify_on_service_flapping)
			payload_new_string(ret, NULL, "f");
		if(state->notify_on_service_downtime)
			payload_new_string(ret, NULL, "s");
		payload_end_array(ret);
	}

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

	time_t now = time(NULL);
	payload_new_boolean(ret, "in_host_notification_period",
		check_time_against_period(now, state->host_notification_period_ptr) == 0);
	payload_new_boolean(ret, "in_service_notification_period",
		check_time_against_period(now, state->service_notification_period_ptr) == 0);

	time_t nexttime;
	get_next_valid_time(now, &nexttime, state->host_notification_period_ptr);
	payload_new_integer(ret, "next_host_notification_time", nexttime);
	get_next_valid_time(now, &nexttime, state->service_notification_period_ptr);
	payload_new_integer(ret, "next_service_notification_time", nexttime);
	
	payload_end_object(ret);
}

static void parse_contactgroup(contactgroup * state, struct payload * ret) {
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

static void parse_downtime(scheduled_downtime * state, struct payload *ret) {
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "scheduled_downtime");
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_integer(ret, "entry_time", state->entry_time);
	payload_new_integer(ret, "start_time", state->start_time);
	payload_new_integer(ret, "end_time", state->end_time);
	payload_new_boolean(ret, "fixed", state->fixed);
	payload_new_integer(ret, "triggered_by", state->triggered_by);
	payload_new_integer(ret, "duration", state->duration);
	payload_new_integer(ret, "downtime_id", state->downtime_id);
	payload_new_string(ret, "author_name", state->author);
	payload_new_string(ret, "comment_data", state->comment);
	payload_new_integer(ret, "comment_id", state->comment_id);
	payload_new_boolean(ret, "is_in_effect", state->is_in_effect);
	payload_new_integer(ret, "start_flex_downtime", state->start_flex_downtime);
	payload_new_integer(ret, "incremented_pending_downtime", state->incremented_pending_downtime);
	payload_end_object(ret);
}

static void parse_comment(comment * state, struct payload * ret) {
	payload_start_object(ret, NULL);
	payload_new_string(ret, "type", "comment");
	payload_new_integer(ret, "entry_type", state->entry_type);
	payload_new_integer(ret, "comment_id", state->comment_id);
	payload_new_integer(ret, "source", state->source);
	payload_new_boolean(ret, "persistent", state->persistent);
	payload_new_integer(ret, "entry_time", state->entry_time);
	payload_new_boolean(ret, "expires", state->expires);
	payload_new_integer(ret, "expire_time", state->expire_time);
	payload_new_string(ret, "host_name", state->host_name);
	payload_new_string(ret, "service_description", state->service_description);
	payload_new_string(ret, "author_name", state->author);
	payload_new_string(ret, "comment_data", state->comment_data);
	payload_end_object(ret);
}

extern scheduled_downtime *scheduled_downtime_list;
static void do_list_downtimes(struct payload * po, json_t * req) {
	int list_downtimes = 0;
	get_values(req,
		"list_downtimes", JSON_TRUE, 0, &list_downtimes,
		NULL);
	if(!list_downtimes)
		return;

	scheduled_downtime * sdlck = scheduled_downtime_list;
	while(sdlck) {
		int ok = 1;
		if(cur_service && sdlck->service_description) {
			if(strcmp(sdlck->service_description, cur_service->description) != 0)
				ok = 0;
			else if(strcmp(sdlck->host_name, cur_service->host_name) != 0)
				ok = 0;
			else if(for_user && !is_contact_for_service(cur_service, for_user))
				ok = 0;
		}
		else if(cur_host) {
			if(strcmp(sdlck->host_name, cur_host->name) != 0)
				ok = 0;
			if(for_user && !is_contact_for_host(cur_host, for_user))
				ok = 0;
		}
		if(ok)
			parse_downtime(sdlck, po);
		sdlck = sdlck->next;
	}
}

extern comment *comment_list;
static void do_list_comments(struct payload * po, json_t * req) {
	int list_comments = 0;
	get_values(req,
		"list_comments", JSON_TRUE, 0, &list_comments,
		NULL);
	if(!list_comments)
		return;

	comment * clck = comment_list;
	while(clck) {
		int ok = 1;
		if(cur_service && clck->service_description) {
			if(strcmp(clck->service_description, cur_service->description) != 0)
				ok = 0;
			else if(strcmp(clck->host_name, cur_service->host_name) != 0)
				ok = 0;
			else if(for_user && !is_contact_for_service(cur_service, for_user))
				ok = 0;
		}
		else if(cur_host) {
			if(strcmp(clck->host_name, cur_host->name) != 0)
				ok = 0;
			if(for_user && !is_contact_for_host(cur_host, for_user))
				ok = 0;
		}
		if(ok)
			parse_comment(clck, po);
		clck = clck->next;
	}
}

static void do_list_hosts(struct payload * po, json_t * req) {
	int list_hosts = 0;
	
	get_values(req,
		"list_hosts", JSON_TRUE, 0, &list_hosts,
		NULL);
	if(!list_hosts)
		return;

	if(!expand_lists) {
		payload_start_object(po, NULL);
		payload_new_string(po, "type", "host_list");
		if(!payload_start_array(po, "hosts")) {
			payload_end_object(po);
			return;
		}
	}
	host * tmp_host = host_list;
	while(tmp_host) {
		if(for_user && !is_contact_for_host(tmp_host, for_user)) {
			tmp_host = tmp_host->next;
			continue;
		}
		if(expand_lists)
			parse_host(tmp_host, po);
		else
			payload_new_string(po, NULL, tmp_host->name);
		tmp_host = tmp_host->next;
	}
	if(!expand_lists) {
		payload_end_array(po);
		payload_end_object(po);
	}
}

static void do_list_hostgroups(struct payload * po, json_t * req) {
	int list_hostgroups = 0;

	get_values(req,
		"list_hostgroups", JSON_TRUE, 0, &list_hostgroups,
		NULL);
	if(!list_hostgroups)
		return;

	if(!expand_lists) {
		payload_start_object(po, NULL);
		payload_new_string(po, "type", "hostgroup_list");
		if(!payload_start_array(po, "hostgroups")) {
			payload_end_object(po);
			return;
		}
	}
	hostgroup * tmp_hostgroup = hostgroup_list;
	while(tmp_hostgroup) {
		if(expand_lists)
			parse_hostgroup(tmp_hostgroup, po);
		else
			payload_new_string(po, NULL, tmp_hostgroup->group_name);
		tmp_hostgroup = tmp_hostgroup->next;
	}
	if(!expand_lists) {
		payload_end_array(po);
		payload_end_object(po);
	}
}

static void do_list_services(struct payload * po, json_t * req) {
	int list_services = 0;
	char * tolist = NULL;

	get_values(req,
		"list_services", JSON_STRING, 0, &tolist,
		"list_services", JSON_TRUE, 0, &list_services,
		NULL);
	if(!list_services && !tolist)
		return;

	if(!expand_lists) {
		payload_start_object(po, NULL);
		payload_new_string(po, "type", "service_list");
		if(!payload_start_array(po, "services")) {
			payload_end_object(po);
			return;
		}
	}
	service * tmp_svc = service_list;
	while(tmp_svc) {
		if(tolist && strcmp(tolist, tmp_svc->description) != 0) {
			tmp_svc = tmp_svc->next;
			continue;
		}
		if(for_user && !is_contact_for_service(tmp_svc, for_user)) {
			tmp_svc = tmp_svc->next;
			continue;
		}
		if(expand_lists)
			parse_service(tmp_svc, po);
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

static void do_list_servicegroups(struct payload * po, json_t * req) {
	int list_servicegroups = 0;
	get_values(req,
		"list_servicegroups", JSON_TRUE, 0, &list_servicegroups,
		NULL);
	if(!list_servicegroups)
		return;

	if(!expand_lists) {
		payload_start_object(po, NULL);
		payload_new_string(po, "type", "servicegroup_list");
		if(!payload_start_array(po, "servicegroups")) {
			payload_end_object(po);
			return;
		}
	}
	servicegroup * tmp_servicegroup = servicegroup_list;
	while(tmp_servicegroup) {
		if(expand_lists)
			parse_servicegroup(tmp_servicegroup, po);
		else
			payload_new_string(po, NULL, tmp_servicegroup->group_name);
		tmp_servicegroup = tmp_servicegroup->next;
	}
	if(!expand_lists) {
		payload_end_array(po);
		payload_end_object(po);
	}
}

static void send_msg(struct payload * po) {
	int rc;
	payload_finalize(po);
	zmq_msg_t outmsg;
	zmq_msg_init_data(&outmsg, po->json_buf, po->bufused, free_cb, NULL);
	do {
		if((rc = zmq_msg_send(&outmsg, reqsock, 0)) == -1 && errno != EINTR) {
			syslog(LOG_ERR, "Error sending state response: %s", zmq_strerror(errno));
			break;
		}
	} while(rc != 0);
	zmq_msg_close(&outmsg);
	if(po->type)
		free(po->type);
	if(po->service_description)
		free(po->service_description);
	if(po->host_name)
		free(po->host_name);
	free(po);
}

static void err_msg(struct payload * po, char * msg, ...) {
	payload_start_object(po, NULL);
	po->use_hash = 0;
	payload_new_string(po, "type", "error");
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

void process_req_msg(zmq_msg_t * reqmsg) {
	json_t * req;
	json_t *keys = NULL;
	char * contact_name = NULL, *contactgroup_name = NULL,
		*servicegroup_name = NULL, *hostgroup_name = NULL,
		*timeperiod_name = NULL;
	
	json_error_t err;
	struct payload * po;
	char * for_username = NULL;

	po = malloc(sizeof(struct payload));
	memset(po, 0, sizeof(struct payload));
	payload_start_array(po, NULL);

	req = json_loadb(zmq_msg_data(reqmsg), zmq_msg_size(reqmsg), 0, &err);
	if(req == NULL) {
		err_msg(po, "Error loading json", "text",err.text,
			"source", err.source, NULL);
		send_msg(po);
		return;
	}

	host_name = NULL;
	service_description = NULL;
	include_services = 0;
	include_hosts = 0;
	include_contacts = 0;
	cur_host = NULL;
	cur_service = NULL;
	for_user = NULL;

	if(get_values(req,
		"host_name", JSON_STRING, 0, &host_name,
		"service_description", JSON_STRING, 0, &service_description,
		"hostgroup_name", JSON_STRING, 0, &hostgroup_name,
		"servicegroup_name", JSON_STRING, 0, &servicegroup_name,
		"contact_name", JSON_STRING, 0, &contact_name,
		"contactgroup_name", JSON_STRING, 0, &contactgroup_name,
		"include_services", JSON_TRUE, 0, &include_services,
		"include_hosts", JSON_TRUE, 0, &include_hosts,
		"include_contacts", JSON_TRUE, 0, &include_contacts,
		"expand_lists", JSON_TRUE, 0, &expand_lists,
		"keys", JSON_ARRAY, 0, &keys,
		"timeperiod_name", JSON_STRING, 0, &timeperiod_name,
		"for_user", JSON_STRING, 0, &for_username,
		NULL) != 0) {
		json_decref(req);
		err_msg(po, "Error unpacking request", NULL);
		send_msg(po);
		return;
	}

	if(for_username && (for_user = find_contact(for_username)) == NULL) {
		err_msg(po, "Error finding contact for authorization",
			"contact_name", for_user);
		send_msg(po);
		return;
	}

	if(keys) {
		int i;
		for(i = 0; i < json_array_size(keys); i++) {
			json_t * keytmp = json_array_get(keys, i);
			if(!json_is_string(keytmp))
				continue;
			payload_hash_key(po, json_string_value(keytmp));
		}
	}

	if(service_description) {
		if(!host_name) {
			err_msg(po, "No host specified for service", "service_description",
				service_description, NULL);
			send_msg(po);
			json_decref(req);
			return;
		}

		cur_service = find_service(host_name, service_description);
		if(!cur_service) {
			err_msg(po, "Could not find service", "service_description",
				service_description, "host_name", host_name, NULL);
			goto end;
		}
		if(for_user && !is_contact_for_service(cur_service, for_user)) {
			err_msg(po, "User not authorized for service", "service_description",
				service_description, "host_name", host_name, NULL);
			goto end;
		}
		
		parse_service(cur_service, po);
	} else if(host_name) {
		cur_host = find_host(host_name);
		if(!cur_host) {
			err_msg(po, "Could not find host", "host_name", host_name, NULL);
			goto end;
		}
		if(for_user && !is_contact_for_host(cur_host, for_user)) {
			err_msg(po, "User not authorized for host", "host_name", host_name, NULL);
			goto end;
		}

		parse_host(cur_host, po);
	}
	if(hostgroup_name) {
		hostgroup * hsttarget = find_hostgroup(hostgroup_name);
		if(hsttarget == NULL) {
			err_msg(po, "Could not find hostgroup", "hostgroup_name",
				hostgroup_name, NULL);
			goto end;
		}
		parse_hostgroup(hsttarget, po);
	}
	if(servicegroup_name) {
		servicegroup * svctarget = find_servicegroup(servicegroup_name);
		if(svctarget == NULL) {
			err_msg(po, "Could not find servicegroup", "servicegroup_name",
				servicegroup_name, NULL);
			goto end;
		}
		parse_servicegroup(svctarget, po);
	}
	if(contactgroup_name) {
		contactgroup * cntarget = find_contactgroup(contactgroup_name);
		if(cntarget == NULL) {
			err_msg(po, "Could not find contactgroup", "contactgroup_name",
				contactgroup_name, NULL);
			goto end;
		}
		parse_contactgroup(cntarget, po);
	}
	if(contact_name) {
		contact * cntarget = find_contact(contact_name);
		if(cntarget == NULL) {
			err_msg(po, "Could not find contact", "contact_name",
				contact_name, NULL);
			goto end;
		}
		parse_contact(cntarget, po);
	}

	if(timeperiod_name) {
		timeperiod * tptarget = find_timeperiod(timeperiod_name);
		if(tptarget == NULL) {
			err_msg(po, "Could not find timeperiod", "timeperiod_name",
				timeperiod_name, NULL);
			goto end;
		}
		parse_timeperiod(tptarget, po);
	}

	do_list_hosts(po, req);
	do_list_services(po, req);
	do_list_hostgroups(po, req);
	do_list_servicegroups(po, req);
	do_list_comments(po, req);
	do_list_downtimes(po, req);

end:
	json_decref(req);
	send_msg(po);
}
