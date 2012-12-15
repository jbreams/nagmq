#include <sys/types.h>
#include <sys/time.h>
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
#include "json.h"
#include "jansson.h"
#include "common.h"

NEB_API_VERSION(CURRENT_NEB_API_VERSION)
static void * nagmq_handle = NULL;
void * zmq_ctx;
nebmodule * handle;
json_t * config;

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	if(config)
		json_decref(config);
	return 0;
}

int handle_pubstartup();
void process_payload(struct payload * payload);

void * getsock(char * forwhat, int type) {
	json_t *connect = NULL, *bind = NULL;
#if ZMQ_VERSION_MAJOR == 2
	int hwm = 0;
#else
	int sndhwm = 0, rcvhwm = 0, backlog = 0, maxmsgsize = 0;
	json_t * accept_filters = NULL;
#endif

#if ZMQ_VERSION_MAJOR == 2
	if(json_unpack(config, "{ s?: { s?:o s?:o s?:i } }",
		forwhat, "connect", &connect, "bind", &bind, "hwm", &hwm) != 0) {
#else
	if(json_unpack(config, "{ s?: { s?:o s?:o s?:i s?:i s?:i s?:i s?:o } }",
		forwhat, "connect", &connect, "bind", &bind, "sndhwm", &sndhwm,
		"rcvhwm", &rcvhwm, "backlog", &backlog, "maxmsgsize", &maxmsgsize,
		"tcpacceptfilters", &accept_filters ) != 0) {
	
#endif
		syslog(LOG_ERR, "Parameter error while creating socket for %s",
			forwhat);
		return NULL;
	}

	if(!connect && !bind)
		return NULL;

	void * sock = zmq_socket(zmq_ctx, type);
	if(sock == NULL) {
		syslog(LOG_ERR, "Error creating socket for %s: %s",
			forwhat, zmq_strerror(errno));
		return NULL;
	}

#if ZMQ_VERSION_MAJOR == 2
	if(hwm > 0 &&
		zmq_setsockopt(sock, ZMQ_HWM, &hwm, sizeof(hwm)) != 0) {
		syslog(LOG_ERR, "Error setting HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}
#else
	if(sndhwm > 0 &&
		zmq_setsockopt(sock, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm)) != 0) {
		syslog(LOG_ERR, "Error setting send HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(rcvhwm > 0 &&
		zmq_setsockopt(sock, ZMQ_RCVHWM, &rcvhwm, sizeof(sndhwm)) != 0) {
		syslog(LOG_ERR, "Error setting receive HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(backlog > 0 &&
		zmq_setsockopt(sock, ZMQ_BACKLOG, &backlog, sizeof(backlog)) != 0) {
		syslog(LOG_ERR, "Error setting connection backlog for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(maxmsgsize > 0 &&
		zmq_setsockopt(sock, ZMQ_MAXMSGSIZE, &maxmsgsize, sizeof(maxmsgsize)) != 0) {
		syslog(LOG_ERR, "Error setting maximum message size for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(accept_filters != NULL && json_is_array(accept_filters)) {
		size_t i, len = json_array_size(accept_filters);
		for(i = 0; i < len; i++) {
			json_t * filterj = json_array_get(accept_filters, i);
			const char * filter = json_string_value(filterj);
			if(!filter) {
				syslog(LOG_ERR, "Filter %i for %s is not a string", i, forwhat);
				zmq_close(sock);
				return NULL;
			}
			size_t flen = strlen(filter);
			if(zmq_setsockopt(sock, ZMQ_TCP_ACCEPT_FILTER, filter, flen) != 0) {
				syslog(LOG_ERR, "Error setting TCP filter %s for %s: %s",
					filter, forwhat, zmq_strerror(errno));
				zmq_close(sock);
				return NULL;
			}
		}
	}
#endif

	if(connect) {
		if(json_is_string(connect) && zmq_connect(sock,
			json_string_value(connect)) != 0) {
			syslog(LOG_ERR, "Error connecting %s to %s: %s",
				forwhat, json_string_value(connect), zmq_strerror(errno));
			zmq_close(sock);
			return NULL;
		} else if(json_is_array(connect)) {
			size_t i;
			for(i = 0; i < json_array_size(connect); i++) {
				json_t * target = json_array_get(connect, i);
				if(zmq_connect(sock, json_string_value(target)) != 0) {
					syslog(LOG_ERR, "Error connecting %s to %s: %s",
						forwhat, json_string_value(target), zmq_strerror(errno));
					zmq_close(sock);
					return NULL;
				}
			}
		}
	}

	if(bind) {
		if(json_is_string(bind) && zmq_bind(sock,
			json_string_value(bind)) != 0) {
			syslog(LOG_ERR, "Error binding %s to %s: %s",
				forwhat, json_string_value(bind), zmq_strerror(errno));
			zmq_close(sock);
			return NULL;
		} else if(json_is_array(bind)) {
			size_t i;
			for(i = 0; i < json_array_size(bind); i++) {
				json_t * target = json_array_get(bind, i);
				if(zmq_bind(sock, json_string_value(target)) != 0) {
					syslog(LOG_ERR, "Error binding %s to %s: %s",
						forwhat, json_string_value(target), zmq_strerror(errno));
					zmq_close(sock);
					return NULL;
				}
			}
		}
	}

	return sock;
}

void * pullsock = NULL, * reqsock = NULL;

int handle_timedevent(int which, void * obj) {
	nebstruct_timed_event_data * data = obj;
	struct timespec * delay = (struct timespec*)data->event_data;
	struct timeval start;
	long timeout;

	if(which != NEBCALLBACK_TIMED_EVENT_DATA)
		return ERROR;
	if(data->type != NEBTYPE_TIMEDEVENT_SLEEP)
		return 0;

	zmq_pollitem_t pollables[2];
	int pollable_count = 0;
	if(pullsock) {
		pollables[0].socket = pullsock;
		pollables[0].events = ZMQ_POLLIN;
		pollable_count++;
	}

	if(reqsock) {
		pollables[pollable_count].socket = reqsock;
		pollables[pollable_count].events = ZMQ_POLLIN;
		pollable_count++;
	}

	if(pollable_count == 0)
		return 0;

	timeout = (delay->tv_sec * ZMQ_POLL_MSEC * 1000) + 
		((delay->tv_nsec / 1000000) * ZMQ_POLL_MSEC);
	gettimeofday(&start, NULL);
	while(zmq_poll(pollables, pollable_count, timeout) > 0 && timeout > 0) {
		int j;
		struct timeval end;
		for(j = 0; j < pollable_count; j++) {
			if(!(pollables[j].revents & ZMQ_POLLIN))
				continue;
			zmq_msg_t payload;
			zmq_msg_init(&payload);
			if(zmq_msg_recv(&payload, pollables[j].socket, 0) == -1)
				continue;

			if(pollables[j].socket == pullsock)
				process_pull_msg(&payload);
			else if(pollables[j].socket == reqsock)
				process_req_msg(&payload, reqsock);
			zmq_msg_close(&payload);
		}

		gettimeofday(&end, NULL);

		end.tv_sec -= start.tv_sec;
		end.tv_usec -= start.tv_usec;
		if(end.tv_usec < 0) {
			end.tv_sec--;
			end.tv_usec += 1000000;
		}

		delay->tv_sec -= end.tv_sec;
		delay->tv_nsec -= end.tv_usec * 1000;
		if(delay->tv_sec < 0)
			delay->tv_sec = 0;
		if(delay->tv_nsec < 0)
			delay->tv_nsec = 0;
		timeout = (long)(delay->tv_sec * ZMQ_POLL_MSEC * 1000) + 
				((delay->tv_nsec / 1000000) * ZMQ_POLL_MSEC);
	}

	return 0;
}

extern void * pubext;

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	struct payload * payload;
	int numthreads = 1, enablepub = 0, enablepull = 0, enablereq = 0;

	if(json_unpack(config, "{ s?:i, s?:{ s:b } s?:{ s:b } s?:{ s:b } }",
		"iothreads", &numthreads, "publish", "enable", &enablepub,
		"pull", "enable", &enablepull, "reply", "enable", &enablereq) != 0) {
		syslog(LOG_ERR, "Parameter error while starting NagMQ");
		return -1;
	}

	if (ps->type == NEBTYPE_PROCESS_EVENTLOOPSTART) {
		if(!enablepub && !enablepull && !enablereq)
			return 0;
		
		zmq_ctx = zmq_init(numthreads);
		if(zmq_ctx == NULL) {
			syslog(LOG_ERR, "Error initialzing ZMQ: %s",
				zmq_strerror(errno));
			return -1;
		}

		if(enablepub && handle_pubstartup() < 0)
			return -1;

		if(enablepull)
			pullsock = getsock("pull", ZMQ_PULL);

		if(enablereq)
			reqsock = getsock("reply", ZMQ_REP);

		if(enablepub) {
			payload = payload_new();
			payload_new_string(payload, "type", "eventloopstart");
			payload_new_timestamp(payload, "timestamp", &ps->timestamp);
			payload_finalize(payload);
			process_payload(payload);
		}
	} else if(ps->type == NEBTYPE_PROCESS_EVENTLOOPEND) {
		if(enablepub) {
			payload = payload_new();
			payload_new_string(payload, "type", "eventloopend");
			payload_new_timestamp(payload, "timestamp", &ps->timestamp);
			payload_finalize(payload);
			process_payload(payload);
			zmq_close(pubext);
		}

		if(enablepull)
			zmq_close(pullsock);
		if(enablereq)
			zmq_close(reqsock);
		zmq_term(zmq_ctx);
	}
	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * lhandle) {
	json_error_t loaderr;
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "NagMQ");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "1.3");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Provides interface into Nagios via ZeroMQ");

	config = json_load_file(localargs, 0, &loaderr);
	if(config == NULL) {
		syslog(LOG_ERR, "Error loading NagMQ config: %s (at %d:%d)",
			loaderr.text, loaderr.line, loaderr.column);
		return -1;
	}

	handle = lhandle;
	neb_register_callback(NEBCALLBACK_PROCESS_DATA, lhandle,
		0, handle_startup);
	neb_register_callback(NEBCALLBACK_TIMED_EVENT_DATA, lhandle,
		0, handle_timedevent);

	return 0;
}

