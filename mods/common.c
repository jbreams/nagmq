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
#include "common.h"

NEB_API_VERSION(CURRENT_NEB_API_VERSION)
static void * nagmq_handle = NULL;
static pthread_t threadid;
static pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t recv_loop_mutex = PTHREAD_MUTEX_INITIALIZER;
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
int handle_pullstartup();
void process_payload(struct payload * payload);

void * getsock(char * forwhat, int type) {
	json_t *connect = NULL, *bind = NULL;
#if ZMQ_VERSION_MAJOR < 3
	int hwm = 0;
#else
	int sndhwm = 0, rcvhwm = 0, backlog = 0, maxmsgsize = 0;
	json_t * accept_filters = NULL;
#endif

#if ZMQ_VERSION_MAJOR < 3
	if(json_unpack(config, "{ s?: { s?:o s?:o s?:i } }",
		forwhat, "connect", &connect, "bind", &bind, "hwm", &hwm) != 0) {
#else
	if(json_unpack(config, "{ s?: { s?:o s?:o s?:i s?:i s?:i s?:i s?:o } }",
		forwhat, "connect", &connect, "bind", &bind, "sndhwm", &hwm,
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

#if ZMQ_VERSION_MAJOR < 3
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

extern void * crpullsock;
void * recv_loop(void * parg) {
	void * pullsock, * reqsock, *intpullbus = NULL, *intreqbus = NULL;
	int enablepull = 0, enablereq = 0, n = 0;
	zmq_pollitem_t pollables[3];
	int rc, npullthreads = 0, nreqthreads = 0;
	pthread_t * threads = NULL;

	sigset_t signal_set;
	sigfillset(&signal_set);
	pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

	pthread_mutex_lock(&recv_loop_mutex);

	if(json_unpack(config, "{ s?:{ s:b s?:i } s?:{ s:b s?:i } }",
		"pull", "enable", &enablepull, "threads", &npullthreads,
		"reply", "enable", &enablereq, "threads", &nreqthreads) != 0) {
		syslog(LOG_ERR, "Parameter error while starting NagMQ");
		return NULL;
	}
	
	if(npullthreads > 0 || nreqthreads > 0) {
		int nthreads = npullthreads + nreqthreads;
		threads = malloc(sizeof(pthread_t) * nthreads);
		memset(threads, 0, sizeof(pthread_t) * nthreads);
	}

	memset(pollables, 0, sizeof(pollables));

	if(enablepull) {
		pullsock = getsock("pull", ZMQ_PULL);
		if(!pullsock)
			return NULL;
		pollables[0].socket = pullsock;
		pollables[0].events = ZMQ_POLLIN;

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
			i = 0;

			for(i = 0; i < npullthreads; i++) {
				if(pthread_create(&threads[n++], NULL, pull_thread, zmq_ctx) != 0) {
					syslog(LOG_ERR, "Error creating pull thread #%d %m", i);
					return NULL;
				}
			}
		}
	}

	if(enablereq) {
		if(nreqthreads > 0) {
			int i;
			reqsock = getsock("reply", ZMQ_ROUTER);
			if(!reqsock)
				return NULL;
			
			intreqbus = zmq_socket(zmq_ctx, ZMQ_DEALER);
			if(!intreqbus) {
				syslog(LOG_ERR, "Error creating internal req bus");
				return NULL;
			}

			zmq_bind(intreqbus, "inproc://nagmq_req_bus");
			for(i = 0; i < nreqthreads; i++) {
				if(pthread_create(&threads[n++], NULL, req_thread, zmq_ctx) != 0) {
					syslog(LOG_ERR, "Error creating req thread #%d %m", i);
					return NULL;
				}
			}

			pollables[2].socket = intreqbus;
			pollables[2].events = ZMQ_POLLIN;
		} else {
			reqsock = getsock("reply", ZMQ_REP);
			if(!reqsock) {
				if(pullsock)
					zmq_close(pullsock);
				return NULL;
			}
		}

		pollables[1].socket = reqsock;
		pollables[1].events = ZMQ_POLLIN;
	}

	pthread_cond_signal(&init_cond);
	pthread_mutex_unlock(&recv_loop_mutex);

	while(1) {
#if #if ZMQ_VERSION_MAJOR < 3
		int64_t more;
#else
		int more;
#endif;
		size_t moresize = sizeof(more);
		zmq_msg_t tmpmsg;

		if((rc = zmq_poll(pollables, 3, -1)) < 0) {
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

		if(enablepull && pollables[0].revents & ZMQ_POLLIN) {
			zmq_msg_init(&tmpmsg);
			if((rc = zmq_recv(pullsock, &tmpmsg, 0)) != 0) {
				zmq_msg_close(&tmpmsg);
				continue;
			}
			if(npullthreads == 0)
				process_pull_msg(&tmpmsg, NULL);
			else {
				zmq_msg_t outmsg;
				zmq_msg_init(&outmsg);
				zmq_msg_copy(&outmsg, &tmpmsg);
				zmq_send(intpullbus, &outmsg, 0);
				zmq_msg_close(&outmsg);
			}
			zmq_msg_close(&tmpmsg);
		}
		if(enablereq && pollables[1].revents & ZMQ_POLLIN) {
			do {
				zmq_msg_init(&tmpmsg);
				if((rc = zmq_recv(reqsock, &tmpmsg, 0)) != 0) {
					zmq_msg_close(&tmpmsg);
					continue;
				}
				if(nreqthreads == 0)
					process_req_msg(&tmpmsg, reqsock);
				else {
					zmq_msg_t outmsg;
					zmq_msg_init(&outmsg);
					zmq_msg_copy(&outmsg, &tmpmsg);
					zmq_getsockopt(reqsock, ZMQ_RCVMORE, &more, &moresize); 
					zmq_send(intreqbus, &outmsg, more ? ZMQ_SNDMORE : 0);
					zmq_msg_close(&outmsg);
				}
				zmq_msg_close(&tmpmsg);
			} while(nreqthreads > 0 && more);
		}
		if(nreqthreads > 0 && pollables[2].revents & ZMQ_POLLIN) {
			do {
				zmq_msg_init(&tmpmsg);
				if((rc = zmq_recv(intreqbus, &tmpmsg, 0)) != 0) {
					zmq_msg_close(&tmpmsg);
					continue;
				}
				zmq_msg_t outmsg;
				zmq_msg_init(&outmsg);
				zmq_msg_copy(&outmsg, &tmpmsg);
				zmq_getsockopt(intreqbus, ZMQ_RCVMORE, &more, &moresize);
				zmq_send(reqsock, &outmsg, more ? ZMQ_SNDMORE : 0);
				zmq_msg_close(&outmsg);
				zmq_msg_close(&tmpmsg);
			} while(more);
		}
	}

	while(n > 0)
		pthread_join(threads[--n], NULL);

	if(enablereq)
		zmq_close(reqsock);
	if(enablepull)
		zmq_close(pullsock);
	if(intpullbus)
		zmq_close(intpullbus);
	if(intreqbus)
		zmq_close(intreqbus);
	if(crpullsock)
		zmq_close(crpullsock);

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
		if(enablereq || enablepull)
			pthread_join(threadid, NULL);
	}
	return 0;
}

int handle_timedevent(int which, void * data);

int nebmodule_init(int flags, char * localargs, nebmodule * lhandle) {
	json_error_t loaderr;
	neb_set_module_info(handle, NEBMODULE_MODINFO_TITLE, "NagMQ");
	neb_set_module_info(handle, NEBMODULE_MODINFO_AUTHOR, "Jonathan Reams");
	neb_set_module_info(handle, NEBMODULE_MODINFO_VERSION, "1.3");
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

