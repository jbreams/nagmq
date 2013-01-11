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
extern void * pubext;
extern int daemon_mode;
json_t * config;

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	if(config)
		json_decref(config);
	return 0;
}

int handle_pubstartup();
void process_payload(struct payload * payload);

void * getsock(char * forwhat, int type, json_t * def) {
	char * connect = NULL, *bind = NULL;
	json_t *connect_array = NULL, *bind_array = NULL;
#if ZMQ_VERSION_MAJOR == 2
	int hwm = 0;
#else
	int sndhwm = 0, rcvhwm = 0, backlog = 0, maxmsgsize = 0;
	json_t * accept_filters = NULL;
#endif

	if(get_values(def,
		"connect", JSON_STRING, 0, &connect,
		"connect", JSON_ARRAY, 0, &connect_array,
		"bind", JSON_STRING, 0, &bind,
		"bind", JSON_ARRAY, 0, &bind_array,
#if ZMQ_VERSION_MAJOR == 2
		"hwm", JSON_INTEGER, 0, &hwm,
#else
		"sndhwm", JSON_INTEGER, 0, &sndhwm,
		"rcvhwm", JSON_INTEGER, 0, &rcvhwm,
		"backlog", JSON_INTEGER, 0, &backlog,
		"maxmsgsize", JSON_INTEGER, 0, &maxmsgsize,
		"tcpacceptfilters", JSON_ARRAY, 0, &accept_filters,	
#endif
		NULL) != 0) {
		syslog(LOG_ERR, "Parameter error while creating socket for %s",
			forwhat);
		return NULL;
	}

	if(!connect && !bind && !connect_array && !bind_array) {
		syslog(LOG_ERR, "Did not specify any connect or binds for %s",
			forwhat);
		return NULL;
	}

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

	if(accept_filters) {
		size_t i, len = json_array_size(accept_filters);
		for(i = 0; i < len; i++) {
			json_t * filterj = json_array_get(accept_filters, i);
			const char * filter = json_string_value(filterj);
			if(!filter) {
				syslog(LOG_ERR, "Filter %d for %s is not a string", i, forwhat);
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

	if(connect && zmq_connect(sock, connect) != 0) {
		syslog(LOG_ERR, "Error connecting %s to %s: %s",
			forwhat, connect, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	} else if(connect_array && !connect) {
		size_t i;
		for(i = 0; i < json_array_size(connect_array); i++) {
			json_t * target = json_array_get(connect_array, i);
			if(zmq_connect(sock, json_string_value(target)) != 0) {
				syslog(LOG_ERR, "Error connecting %s to %s: %s",
					forwhat, json_string_value(target), zmq_strerror(errno));
				zmq_close(sock);
				return NULL;
			}
		}
	}

	if(bind && zmq_bind(sock, bind) != 0) {
		syslog(LOG_ERR, "Error binding %s to %s: %s",
			forwhat, bind, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	} else if(bind_array && !bind) {
		size_t i;
		for(i = 0; i < json_array_size(bind_array); i++) {
			json_t * target = json_array_get(bind_array, i);
			if(zmq_bind(sock, json_string_value(target)) != 0) {
				syslog(LOG_ERR, "Error binding %s to %s: %s",
					forwhat, json_string_value(target), zmq_strerror(errno));
				zmq_close(sock);
				return NULL;
			}
		}
	}

	return sock;
}

void * pullsock = NULL, * reqsock = NULL;
extern void * pubext;

int handle_timedevent(int which, void * obj) {
	nebstruct_timed_event_data * data = obj;
	struct timespec * delay = NULL;
	struct timeval start;
	int nevents = 0;
	long timeout = 0, diff;

	if(which != NEBCALLBACK_TIMED_EVENT_DATA)
		return ERROR;
	if(data->type != NEBTYPE_TIMEDEVENT_SLEEP)
		return 0;

	zmq_pollitem_t pollables[2];
	memset(pollables, 0, sizeof(pollables));
	if(pullsock) {
		pollables[0].socket = pullsock;
		pollables[0].events = ZMQ_POLLIN;
	}

	if(reqsock) {
		pollables[1].socket = reqsock;
		pollables[1].events = ZMQ_POLLIN;
	}


	delay = (struct timespec*)data->event_data;
	timeout = (delay->tv_sec * 1000 * ZMQ_POLL_MSEC) +
		((delay->tv_nsec / 1000000) * ZMQ_POLL_MSEC);
	gettimeofday(&start, NULL);

	if(zmq_poll(pollables, 2, timeout) < 1) {
		delay->tv_sec = 0;
		delay->tv_nsec = 0;
		return 0;
	}

	do {
		struct timeval end;
		int j;
		for(j = 0; j < 2; j++) {
			if(!(pollables[j].revents & ZMQ_POLLIN))
				continue;
			zmq_msg_t input;
			zmq_msg_init(&input);
			if(zmq_msg_recv(&input, pollables[j].socket, 0) == -1) {
                		syslog(LOG_ERR, "Error receiving message in sleep handler: %s",
					zmq_strerror(errno));
				continue;
			}

			if(pollables[j].socket == pullsock)
				process_pull_msg(&input);
			else if(pollables[j].socket == reqsock)
				process_req_msg(&input, reqsock);
			zmq_msg_close(&input);
		}

		gettimeofday(&end, NULL);
		diff = ((end.tv_sec - start.tv_sec) * 1000000) +
			(end.tv_usec - start.tv_usec);
		if(diff / 1000 >= timeout)
			break;
	} while(nevents > 0);

	if(diff / 1000 >= timeout) {
		delay->tv_sec = 0;
		delay->tv_nsec = 0;
	} else {
		delay->tv_sec = diff / 1000000;
		diff -= delay->tv_sec * 1000000;
		delay->tv_nsec = diff > 1 ? diff * 1000 : 0;
	}

	return 0;
}

void input_reaper(void * insock) {
	while(1) {
		zmq_msg_t input;
		zmq_msg_init(&input);

		if(zmq_msg_recv(&input, insock, ZMQ_DONTWAIT) == -1) {
			if(errno == EAGAIN)
				break;
			else if(errno == EINTR)
				continue;
			syslog(LOG_ERR, "Error receiving message from command interface: %s",
				zmq_strerror(errno));
			continue;
		}

		if(insock == pullsock)
			process_pull_msg(&input);
		else if(insock == reqsock)
			process_req_msg(&input, reqsock);

		zmq_msg_close(&input);
	}
}

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	time_t now = ps->timestamp.tv_sec;

	switch(ps->type) {
		case NEBTYPE_PROCESS_START:
			if(daemon_mode)
				return 0;
		case NEBTYPE_PROCESS_DAEMONIZE: {
			json_t * pubdef = NULL, *pulldef = NULL, *reqdef = NULL;
			int numthreads = 1;

			if(get_values(config,
				"iothreads", JSON_INTEGER, 0, &numthreads,
				"publish", JSON_OBJECT, 0, &pubdef,
				"pull", JSON_OBJECT, 0, &pulldef,
				"reply", JSON_OBJECT, 0, &reqdef,
				NULL) != 0) {
				syslog(LOG_ERR, "Parameter error while starting NagMQ");
				return -1;
			}
		
			if(!pubdef && !pulldef && !reqdef)
				return 0;
			
			zmq_ctx = zmq_init(numthreads);
			if(zmq_ctx == NULL) {
				syslog(LOG_ERR, "Error initialzing ZMQ: %s",
					zmq_strerror(errno));
				return -1;
			}

			if(pubdef && handle_pubstartup(pubdef) < 0)
				return -1;

			if(pulldef) {
				unsigned long interval = 2;
				get_values(pulldef,
					"interval", JSON_INTEGER, 0, &interval,
					NULL);
				if((pullsock = getsock("pull", ZMQ_PULL, pulldef)) == NULL)
					return -1;
				schedule_new_event(EVENT_USER_FUNCTION, 1, now, 1, interval,
					NULL, 1, input_reaper, pullsock, 0);
			}

			if(reqdef) {
				unsigned long interval = 2;
				get_values(reqdef,
					"interval", JSON_INTEGER, 0, &interval,
					NULL);
				if((reqsock = getsock("reply", ZMQ_REP, reqdef)) == NULL)
					return -1;
				schedule_new_event(EVENT_USER_FUNCTION, 1, now, 1, interval,
					NULL, 1, input_reaper, reqsock, 0);
			}

			if(pulldef || reqdef)
				neb_register_callback(NEBCALLBACK_TIMED_EVENT_DATA, handle, 0, handle_timedevent);
			break;
		}
		case NEBTYPE_PROCESS_SHUTDOWN:
			if(pullsock)
				zmq_close(pullsock);
			if(reqsock)
				zmq_close(reqsock);
			if(pubext)
				zmq_close(pubext);
			zmq_term(zmq_ctx);
			break;
		case NEBTYPE_PROCESS_EVENTLOOPSTART:
		case NEBTYPE_PROCESS_EVENTLOOPEND:
			if(pubext) {
				struct payload * payload;
				payload = payload_new();
				switch(ps->type) {
					case NEBTYPE_PROCESS_EVENTLOOPSTART:
						payload_new_string(payload, "type", "eventloopstart");
						break;
					case NEBTYPE_PROCESS_EVENTLOOPEND:
						payload_new_string(payload, "type", "eventloopend");
						break;
				}
				payload_new_timestamp(payload, "timestamp", &ps->timestamp);
				payload_finalize(payload);
				process_payload(payload);
			}
			break;
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

	return 0;
}

