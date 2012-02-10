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
#include <jansson.h>
#include <pthread.h>

static void * nagmq_handle = NULL;
static pthread_cond_t queue_event;
static pthread_mutex_t queue_mutex;
static pthread_t queue_thread;
static int queuestatus = 0;
extern int errno;
static char * args = NULL;

struct pq {
	json_t * payload;
	struct pq * next;
};

static struct pq * head = NULL, *tail = NULL;

static void enqueue(json_t * payload) {
	struct pq * tmp = malloc(sizeof(struct pq));
	tmp->payload = payload;
	tmp->next = NULL;
	pthread_mutex_lock(&queue_mutex);
	if(tail == NULL) {
		tail = tmp;
		head = tmp;
	} else {
		tail->next = tmp;
	}
	pthread_mutex_unlock(&queue_mutex);
}

static struct pq * dequeue() {
	struct pq * lock;
	pthread_mutex_lock(&queue_mutex);
	lock = head;
	head = NULL;
	tail = NULL;
	pthread_mutex_unlock(&queue_mutex);
	return lock;
}

NEB_API_VERSION(CURRENT_NEB_API_VERSION)

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	pthread_mutex_lock(&queue_mutex);
	queuestatus = 1;
	pthread_mutex_unlock(&queue_mutex);
	pthread_join(queue_thread, NULL);
	if(args)
		free(args);
	pthread_cond_destroy(&queue_event);
	pthread_mutex_destroy(&queue_mutex);
	while(head) {
		tail = head->next;
		json_decref(head->payload);
		free(head);
		head = tail;
	}
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
	json_t * payload;
	switch(which) {
	case NEBCALLBACK_HOST_CHECK_DATA:
		payload = parse_host_check(obj);
		break;
	case NEBCALLBACK_SERVICE_CHECK_DATA:
		payload = parse_service_check(obj);
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

	enqueue(payload);
	return 0;
}

static void sigback(int err) {
	queuestatus = err;
	pthread_mutex_lock(&queue_mutex);
	pthread_cond_broadcast(&queue_event);
	pthread_mutex_unlock(&queue_mutex);
}

static void process_payload(json_t * payload, void * sock) {
	zmq_msg_t type, dump;
	char * payloadstr;
	int rc;

	json_t * jtype = json_object_get(payload, "type");
	size_t slen = strlen(json_string_value(jtype));
	zmq_msg_init_size(&type, slen);
	memcpy(zmq_msg_data(&type), json_string_value(jtype), slen);
	rc = zmq_send(sock, &type, ZMQ_SNDMORE);
	zmq_msg_close(&type);
	if(rc != 0) {
		syslog(LOG_ERR, "Error sending type header: %s",
			zmq_strerror(rc));
		json_decref(payload);
		return;
	}

	payloadstr = json_dumps(payload, JSON_COMPACT);
	zmq_msg_init_data(&dump, payloadstr, strlen(payloadstr), free_cb, NULL);
	if((rc = zmq_send(sock, &dump, 0)) != 0)
		syslog(LOG_ERR, "Error sending payload: %s",
			zmq_strerror(rc));
	zmq_msg_close(&dump);
	json_decref(payload);
}

static void zmq_queue_runner(void * nouse) {
	void * zmq_ctx;
	void * pubext;
	int numthreads = 1, rc, sleeptime = 5;
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
		else if(strcmp(name, "sleepfor") == 0)
			sleeptime = atoi(val);
	}

	zmq_ctx = zmq_init(numthreads);
	if(zmq_ctx == NULL) {
		syslog(LOG_ERR, "Error intializing ZMQ context: %s",
			zmq_strerror(errno));
		sigback(1);
		return;
	}

	pubext = zmq_socket(zmq_ctx, ZMQ_PUB);
	if(pubext == NULL) {
		syslog(LOG_ERR, "Error creating ZMQ socket: %s",
			zmq_strerror(errno));
		sigback(1);
		return;
	}

	rc = zmq_bind(pubext, bindto);
	if(rc != 0) {
		syslog(LOG_ERR, "Error binding to %s: %s",
			bindto, zmq_strerror(errno));
		sigback(1);
		return;
	}
	
	sigback(0);
	while(queuestatus == 0) {
		struct pq * plock = dequeue();
		while(plock) {
			struct pq * next = plock->next;
			process_payload(plock->payload, pubext);
			free(plock);
			plock = next;
		}
		sleep(sleeptime);
	}

	zmq_close(pubext);
	zmq_term(zmq_ctx);
}

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	if (ps->type == NEBTYPE_PROCESS_EVENTLOOPSTART) {
		pthread_t thread;
		pthread_cond_init(&queue_event, NULL);
		if(pthread_create(&queue_thread, NULL, zmq_queue_runner, NULL) != 0) {
			syslog(LOG_ERR, "Error creating forwarding thread: %m");
			return -1;
		}

		pthread_mutex_lock(&queue_mutex);
		pthread_cond_wait(&queue_event, &queue_mutex);
		pthread_mutex_unlock(&queue_mutex);
		if(queuestatus != 0)
			return -1;

		pthread_detach(queue_thread);
	}
	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * handle) {
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq sink");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "0.1");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Sink for publishing nagios data to ZMQ");

	neb_register_callback(NEBCALLBACK_HOST_CHECK_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_SERVICE_CHECK_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_HOST_STATUS_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_SERVICE_STATUS_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_ACKNOWLEDGEMENT_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_STATE_CHANGE_DATA, handle,
		0, handle_nagdata);
	neb_register_callback(NEBCALLBACK_PROCESS_DATA, handle,
		0, handle_startup);

	nagmq_handle = handle;
	args = strdup(localargs);

	return 0;
}
