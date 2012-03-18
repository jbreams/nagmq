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
#include "json.h"
#include "jansson.h"

NEB_API_VERSION(CURRENT_NEB_API_VERSION)
static skiplist * lock_skiplist;
static void * nagmq_handle = NULL;
static pthread_t threadid;
static pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t recv_loop_mutex = PTHREAD_MUTEX_INITIALIZER;
void * zmq_ctx;
nebmodule * handle;
json_t * config;

struct lock_skip_obj {
	char * host_name;
	char * service_description;
	char * plugin_output;
	char * long_plugin_output;
	char * perf_data;
	pthread_mutex_t lock;
};

int lock_obj_compare(void * ar, void * br) {
	struct lock_skip_obj *a = ar, *b = br;
	int r;
	if(a->service_description || b->service_description) {
		if(a->service_description && !b->service_description)
			return -1;
		else if(!a->service_description && b->service_description)
			return 1;
		else if((r = strcmp(a->service_description, b->service_description)) != 0)
			return r;
	}
	if((r = strcmp(a->host_name, b->host_name)) != 0)
		return r;
	return 0;
}

void lock_obj(char * hostname, char * service, char ** plugin_output,
	char ** long_plugin_output, char ** perf_data) {
	if(!lock_skiplist)
		return;
	struct lock_skip_obj test = { hostname, service, NULL, NULL, NULL,
		PTHREAD_MUTEX_INITIALIZER };
	struct lock_skip_obj * lock = skiplist_find_first(lock_skiplist, &test, NULL);
	if(lock == NULL) {
		lock = malloc(sizeof(struct lock_skip_obj));
		memset(lock, 0, sizeof(struct lock_skip_obj));
		lock->host_name = strdup(hostname);
		if(service)
			lock->service_description = strdup(service);
		else
			lock->service_description = NULL;
		pthread_mutex_init(&lock->lock, NULL);
		skiplist_insert(lock_skiplist, lock);
	}

	if(plugin_output)
		*plugin_output = lock->plugin_output;
	if(long_plugin_output)
		*long_plugin_output = lock->long_plugin_output;
	if(perf_data)
		*perf_data = lock->perf_data;

	pthread_mutex_lock(&lock->lock);
}

void unlock_obj(char * hostname, char * service, char * plugin_output,
	char * long_plugin_output, char * perf_data) {
	if(!lock_skiplist)
		return;
	struct lock_skip_obj test = { hostname, service, NULL, NULL, NULL,
		PTHREAD_MUTEX_INITIALIZER };
	struct lock_skip_obj * lock = skiplist_find_first(lock_skiplist, &test, NULL);
	if(lock == NULL) {
		lock = malloc(sizeof(struct lock_skip_obj));
		memset(lock, 0, sizeof(struct lock_skip_obj));
		lock->host_name = strdup(hostname);
		if(service)
			lock->service_description = strdup(service);
		else
			lock->service_description = NULL;
		pthread_mutex_init(&lock->lock, NULL);
		skiplist_insert(lock_skiplist, lock);
	}

	if(plugin_output) {
		if(lock->plugin_output)
			free(lock->plugin_output);
		lock->plugin_output = strdup(plugin_output);
	}
	if(long_plugin_output) {
		if(lock->long_plugin_output)
			free(lock->long_plugin_output);
		lock->long_plugin_output = strdup(long_plugin_output);
	}
	if(perf_data) {
		if(lock->perf_data)
			free(lock->perf_data);
		lock->perf_data = strdup(perf_data);
	}

	pthread_mutex_unlock(&lock->lock);
}

int nebmodule_deinit(int flags, int reason) {
	neb_deregister_module_callbacks(nagmq_handle);
	if(config)
		json_decref(config);
	struct lock_skip_obj * lock;
	while((lock = skiplist_pop(lock_skiplist)) != NULL) {
		if(lock->service_description)
			free(lock->service_description);
		free(lock->host_name);
		if(lock->plugin_output)
			free(lock->plugin_output);
		if(lock->long_plugin_output)
			free(lock->long_plugin_output);
		if(lock->perf_data)
			free(lock->perf_data);
		pthread_mutex_destroy(&lock->lock);
		free(lock);
	}
	skiplist_free(&lock_skiplist);
	return 0;
}

int handle_pubstartup();
int handle_pullstartup();
void process_payload(struct payload * payload);

void * getsock(char * forwhat, int type) {
	json_t *connect = NULL, *bind = NULL;
	int hwm = 0;

	if(json_unpack(config, "{ s?: { s?:o s?:o s?:i } }",
		forwhat, "connect", &connect, "bind", &bind, "hwm", &hwm) != 0) {
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

	if(hwm > 0 &&
		zmq_setsockopt(sock, ZMQ_HWM, &hwm, sizeof(hwm)) != 0) {
		syslog(LOG_ERR, "Error setting HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

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

void process_req_msg(void * sock);
void process_pull_msg(void * sock, void * ressock);
extern void * crpullsock;
void * pull_thread(void * arg);

void * recv_loop(void * parg) {
	void * pullsock, * reqsock, *intpullbus = NULL;
	int enablepull = 0, enablereq = 0;
	zmq_pollitem_t pollables[2];
	int npollables = 0, rc, npullthreads = 0;

	sigset_t signal_set;
	sigfillset(&signal_set);
	pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

	pthread_mutex_lock(&recv_loop_mutex);

	if(json_unpack(config, "{ s?:{ s:b } s?:{ s:b } }",
		"pull", "enable", &enablepull, "threads", &npullthreads,
		"reply", "enable", &enablereq) != 0) {
		syslog(LOG_ERR, "Parameter error while starting NagMQ");
		return NULL;
	}
	
	if(enablepull) {
		pullsock = getsock("pull", ZMQ_PULL);
		if(!pullsock)
			return NULL;
		pollables[npollables].socket = pullsock;
		pollables[npollables++].events = ZMQ_POLLIN;

		if(npullthreads > 0) {
			int i;
			intpullbus = zmq_socket(zmq_ctx, ZMQ_PUSH);
			if(intpullbus == NULL) {
				syslog(LOG_ERR, "Error creating internal pull bus");
				return NULL;
			}
			zmq_bind(intpullbus, "inproc://nagmq_pull_bus");

			crpullsock = zmq_socket(zmq_ctx, ZMQ_PULL);
			if(crpullsock == NULL) {
				syslog(LOG_ERR, "Error creating internal check result bus");
				return NULL;
			}
			zmq_bind(crpullsock, "inproc://nagmq_cr_bus");

			for(i = 0; i < npullthreads; i++) {
				pthread_t curthread;
				if(pthread_create(&curthread, NULL, pull_thread, NULL) != 0) {
					syslog(LOG_ERR, "Error creating pull thread #%d %m", i);
					return NULL;
				}
			}
		}
	}

	if(enablereq) {
		reqsock = getsock("reply", ZMQ_REP);
		if(!reqsock) {
			if(pullsock)
				zmq_close(pullsock);
			return NULL;
		}
		pollables[npollables].socket = reqsock;
		pollables[npollables++].events = ZMQ_POLLIN;
	}

	lock_skiplist = skiplist_new(15, 0.5, 0, 0, lock_obj_compare);
	pthread_cond_signal(&init_cond);
	pthread_mutex_unlock(&recv_loop_mutex);

	while(1) {
		int events;
		size_t size = sizeof(events);
		if((rc = zmq_poll(pollables, npollables, -1)) < 0) {
			rc = errno;
			if(rc == ETERM)
				break;
			else if(rc == EINTR)
				continue;
			else {
				syslog(LOG_ERR, "Error polling for events: %s",
					zmq_strerror(rc));
				continue;
			}
		}

		if(enablepull) {
			zmq_getsockopt(pullsock, ZMQ_EVENTS, &events, &size);
			if(events == ZMQ_POLLIN) {
				if(npullthreads == 0)
					process_pull_msg(pullsock, NULL);
				else {
					zmq_msg_t tmpmsg;
					zmq_msg_init(&tmpmsg);
					if(zmq_recv(pullsock, &tmpmsg, 0) == 0)
						zmq_send(intpullbus, &tmpmsg, 0);
					zmq_msg_close(&tmpmsg);
				}
			}
		}
		if(enablereq) {
			zmq_getsockopt(reqsock, ZMQ_EVENTS, &events, &size);
			if(events == ZMQ_POLLIN)
				process_req_msg(reqsock);
		}
	}

	if(enablereq)
		zmq_close(reqsock);
	if(enablepull)
		zmq_close(pullsock);
	return NULL;
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

		if(!enablepull && !enablereq)
			return 0;

		pthread_mutex_lock(&recv_loop_mutex);
		if(pthread_create(&threadid, NULL, recv_loop, NULL) < 0) {
			syslog(LOG_ERR, "Error creating ZMQ recv loop: %m");
			return -1;
		}
		pthread_cond_wait(&init_cond, &recv_loop_mutex);
		pthread_detach(threadid);

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
		}

		zmq_close(pubext);
		zmq_term(zmq_ctx);
		pthread_join(threadid, NULL);
	}
	return 0;
}

int handle_timedevent(int which, void * data);

int nebmodule_init(int flags, char * localargs, nebmodule * lhandle) {
	json_error_t loaderr;
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "nagmq subscriber");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "0.8");
	neb_set_module_info(handle, NEBMODULE_MODINFO_LICENSE, "Apache v2");
	neb_set_module_info(handle, NEBMODULE_MODINFO_DESC,
		"Subscribes to Nagios data on 0MQ");

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

