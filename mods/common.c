#include "config.h"
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#define NSCORE 1
#include "nebstructs.h"
#include "nebcallbacks.h"
#include "nebmodules.h"
#include "nebmods.h"
#ifdef HAVE_ICINGA
#include "icinga.h"
#else
#include "nagios.h"
#endif
#include "objects.h"
#include "broker.h"
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
extern int sigrestart;
json_t * config;
char * curve_publickey = NULL, *curve_privatekey = NULL,
	*curve_knownhosts = NULL;
int keyfile_refresh_interval = 60;

// This is defined in nagios's objects.c, it should match the current
// ABI version of the nagios nagmq is loaded into.
extern int __nagios_object_structure_version;

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	if(config)
		json_decref(config);
	return 0;
}

void * pullsock = NULL, * reqsock = NULL;
extern void * pubext;

#ifndef HAVE_NAGIOS4
int handle_timedevent(int which, void * obj) {
	nebstruct_timed_event_data * data = obj;
	struct timespec * delay = NULL;
	struct timeval start;
	int nevents;
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
		nevents = 0;
		for(j = 0; j < 2; j++) {
			zmq_msg_t input;
			zmq_msg_init(&input);
			if(zmq_msg_recv(&input, pollables[j].socket, ZMQ_DONTWAIT) == -1) {
				if(errno != EAGAIN)
					syslog(LOG_ERR, "Error receiving message in sleep handler: %s",
						zmq_strerror(errno));
				continue;
			}

			if(pollables[j].socket == pullsock)
				process_pull_msg(&input);
			else if(pollables[j].socket == reqsock)
				process_req_msg(&input);
			zmq_msg_close(&input);
			nevents++;
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
#endif

void input_reaper(void * insock) {
	while(1) {
		zmq_msg_t input;
		zmq_msg_init(&input);

		if(zmq_msg_recv(&input, insock, ZMQ_DONTWAIT) == -1) {
			if(errno == EAGAIN)
				break;
			else if(errno == EINTR)
				continue;
			syslog(LOG_ERR, "Error receiving message from interface: %s",
				zmq_strerror(errno));
			continue;
		}

		if(insock == pullsock)
			process_pull_msg(&input);
		else if(insock == reqsock)
			process_req_msg(&input);

		zmq_msg_close(&input);
	}
}

#ifdef HAVE_NAGIOS4
int brokered_input_reaper(int sd, int events, void * arg) {
	input_reaper(arg);
	return 0;
}

extern iobroker_set *nagios_iobs;
#endif

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	time_t now = ps->timestamp.tv_sec;
	int rc;

	switch(ps->type) {
		case NEBTYPE_PROCESS_EVENTLOOPSTART:
		{
			json_t * pubdef = NULL, *pulldef = NULL,
				*reqdef = NULL, *curvedef = NULL;
			int numthreads = 1;

			syslog(LOG_INFO, "Initializing NagMQ %u", getpid());
			if(get_values(config,
				"iothreads", JSON_INTEGER, 0, &numthreads,
				"publish", JSON_OBJECT, 0, &pubdef,
				"pull", JSON_OBJECT, 0, &pulldef,
				"reply", JSON_OBJECT, 0, &reqdef,
#if ZMQ_VERSION_MAJOR > 3
				"curve", JSON_OBJECT, 0, &curvedef,
#endif
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

#if ZMQ_VERSION_MAJOR > 3

			if(curvedef) {
				if(get_values(curvedef,
					"publickey", JSON_STRING, 1, &curve_publickey,
					"privatekey", JSON_STRING, 1, &curve_privatekey,
					"clientkeyfile", JSON_STRING, 0, &curve_knownhosts,
					NULL) != 0) {
					syslog(LOG_ERR, "Error getting public/private key for curve security");
					return -1;
				}

				if(curve_knownhosts) {
					pthread_t tid;

					void * zapsock = zmq_socket(zmq_ctx, ZMQ_REP);
					if(zapsock == NULL) {
						syslog(LOG_ERR, "Error creating ZAP socket");
						return -1;
					}

					if(zmq_bind(zapsock, "inproc://zeromq.zap.01") != 0) {
						syslog(LOG_ERR, "Error binding to ZAP endpoint");
						return -1;
					}
					int rc = pthread_create(&tid, NULL, zap_handler, zapsock);
					if(rc != 0) {
						syslog(LOG_ERR, "Error starting ZAP thread?");
						return -1;
					}
				}
			}
#endif

			if(pubdef && handle_pubstartup(pubdef) < 0)
				return -1;

			if(pulldef) {
				unsigned long interval = 2;
				get_values(pulldef,
					"interval", JSON_INTEGER, 0, &interval,
					NULL);
				if((pullsock = getsock("pull", ZMQ_PULL, pulldef)) == NULL)
					return -1;
#ifdef HAVE_NAGIOS4
				int fd;
				size_t throwaway = sizeof(fd);
				zmq_getsockopt(pullsock, ZMQ_FD, &fd, &throwaway);
				iobroker_register(nagios_iobs, fd, pullsock, brokered_input_reaper);
#else
				schedule_new_event(EVENT_USER_FUNCTION, 1, now, 1, interval,
					NULL, 1, input_reaper, pullsock, 0);
#endif
				setup_sockmonitor(pullsock);
				// Call the input_reaper once manually to clear out any
				// level-triggered polling problems.
				input_reaper(pullsock);
			}

			if(reqdef) {
				unsigned long interval = 2;
				get_values(reqdef,
					"interval", JSON_INTEGER, 0, &interval,
					NULL);
				if((reqsock = getsock("reply", ZMQ_REP, reqdef)) == NULL)
					return -1;
#ifdef HAVE_NAGIOS4
				int fd;
				size_t throwaway = sizeof(fd);
				zmq_getsockopt(reqsock, ZMQ_FD, &fd, &throwaway);
				iobroker_register(nagios_iobs, fd, reqsock, brokered_input_reaper);
#else
				schedule_new_event(EVENT_USER_FUNCTION, 1, now, 1, interval,
					NULL, 1, input_reaper, reqsock, 0);
#endif
				setup_sockmonitor(reqsock);
				// Call the input_reaper once manually to clear out any
				// level-triggered polling problems.
				input_reaper(reqsock);
			}

#ifndef HAVE_NAGIOS4
			if(pulldef || reqdef)
				neb_register_callback(NEBCALLBACK_TIMED_EVENT_DATA, handle, 0, handle_timedevent);
#endif
			break;
		}
		case NEBTYPE_PROCESS_EVENTLOOPEND:
			if(pubext) {
				struct payload * payload;
				payload = payload_new();
				payload_new_string(payload, "type", "eventloopend");
				payload_new_timestamp(payload, "timestamp", &ps->timestamp);
				payload_finalize(payload);
				process_payload(payload);
			}
			if(pullsock) {
#ifdef HAVE_NAGIOS4
				int fd;
				size_t throwaway = sizeof(fd);
				zmq_getsockopt(pullsock, ZMQ_FD, &fd, &throwaway);
				iobroker_unregister(nagios_iobs, fd);
#endif
				zmq_close(pullsock);
			}
			if(reqsock) {
#ifdef HAVE_NAGIOS4
				int fd;
				size_t throwaway = sizeof(fd);
				zmq_getsockopt(reqsock, ZMQ_FD, &fd, &throwaway);
				iobroker_unregister(nagios_iobs, fd);
#endif
				zmq_close(reqsock);
			}
			if(pubext)
				zmq_close(pubext);

			while((rc = zmq_term(zmq_ctx)) != 0) {
				if(errno == EINTR) {
					syslog(LOG_DEBUG, "NagMQ ZeroMQ context termination was interrupted");
					continue;
				}
				else
					break;
			}
			break;
	}
	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * lhandle) {
	json_error_t loaderr;
	handle = lhandle;

	if(__nagios_object_structure_version != CURRENT_OBJECT_STRUCTURE_VERSION) {
		syslog(LOG_ERR, "NagMQ is loaded into a version of nagios with a different ABI " \
			"than it was compiled for! You need to recompile NagMQ against the current " \
			"nagios headers!");
		return -1;
	}

	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "NagMQ");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "1.4");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Provides interface into Nagios via ZeroMQ");

	config = json_load_file(localargs, 0, &loaderr);
	if(config == NULL) {
		syslog(LOG_ERR, "Error loading NagMQ config: %s (at %d:%d)",
			loaderr.text, loaderr.line, loaderr.column);
		return -1;
	}

	neb_register_callback(NEBCALLBACK_PROCESS_DATA, lhandle,
		0, handle_startup);

	return 0;
}

