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
#include <pthread.h>

static void * nagmq_handle = NULL;
static pthread_cond_t queue_event;
static pthread_mutex_t queue_mutex;
static int queuestatus = 0;
extern int errno;
static int curwhich;

NEB_API_VERSION(CURRENT_NEB_API_VERSION)

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	pthread_mutex_lock(&queue_mutex);
	queuestatus = 1;
	pthread_cond_signal(&queue_event);
	pthread_mutex_unlock(&queue_mutex);
	return 0;
}

static json_t * parse_timestamp(struct timeval * tv) {
	json_t * ret = json_object();
	json_object_set_new(ret, "tv_sec", json_integer(tv->tv_sec));
	json_object_set_new(ret, "tv_usec", json_integer(tv->tv_usec));
	return ret;
}

void free_cb(void * ptr, void * hint) {
	free(ptr);
}

int handle_nagdata(int which, void * obj) {
	pthread_mutex_lock(&queue_mutex);
	curwhich = which;
	pthread_cond_signal(&queue_event);
	pthread_mutex_unlock(&queue_mutex);
	return 0;
}

static void sigback(int err) {
	queuestatus = err;
	pthread_mutex_lock(&queue_mutex);
	pthread_cond_broadcast(&queue_event);
	pthread_mutex_unlock(&queue_mutex);
}

static void zmq_queue_runner(void * args) {
	void * zmq_ctx;
	void * pubext;
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
		if(strcmp(name, "bind") == 0) {
			bindto = val;
		}
		else if(strcmp(name, "numthreads") == 0) {
			numthreads = atoi(val);
		}
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
	unsigned long eventcounter = 0;
	while(queuestatus == 0) {
		pthread_mutex_lock(&queue_mutex);
		pthread_cond_wait(&queue_event, &queue_mutex);
		syslog(LOG_INFO, "Received new event #%d type %d",
			eventcounter++, curwhich);
		pthread_mutex_unlock(&queue_mutex);
	}

	zmq_close(pubext);
	zmq_term(zmq_ctx);
}

int nebmodule_init(int flags, char * args, nebmodule * handle) {
	char * bindto = NULL;
	int numthreads = 1, rc;
	pthread_t thread, intsetupthread;

	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq sink");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "0.1");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Sink for publishing nagios data to ZMQ");

	pthread_cond_init(&queue_event, NULL);
	rc = pthread_create(&thread, NULL, zmq_queue_runner, args);
	if(rc != 0) {
		syslog(LOG_ERR, "Error creating forwarding thread: %m");
		return -1;
	}

	pthread_mutex_lock(&queue_mutex);
	pthread_cond_wait(&queue_event, &queue_mutex);
	pthread_mutex_unlock(&queue_mutex);
	if(queuestatus != 0)
		return -1;

	pthread_detach(thread);

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
