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
				syslog(LOG_ERR, "Filter %lu for %s is not a string", i, forwhat);
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

#if ZMQ_VERSION_MAJOR > 3
	if(curve_privatekey) {
		int yes = 1, rc;
		rc = zmq_setsockopt(sock, ZMQ_CURVE_SECRETKEY,
			curve_privatekey, strlen(curve_privatekey));
		if(rc == -1) {
			syslog(LOG_ERR, "Error setting secret key for %s %s %d %s",
				forwhat, curve_privatekey, strlen(curve_privatekey), zmq_strerror(errno));
			zmq_close(sock);
			return NULL;
		}
		rc = zmq_setsockopt(sock, ZMQ_CURVE_PUBLICKEY,
			curve_privatekey, strlen(curve_publickey));
		if(rc == -1) {
			syslog(LOG_ERR, "Error setting public key for %s %s %s",
				forwhat, curve_privatekey, zmq_strerror(errno));
			zmq_close(sock);
			return NULL;
		}
		zmq_setsockopt(sock, ZMQ_CURVE_SERVER, &yes, sizeof(int));
		syslog(LOG_INFO, "Set up curve security in NagMQ");
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

#if ZMQ_VERSION_MAJOR > 3
struct keybag {
	uint8_t key[32];
	struct keybag * next;
};

struct keybaghash {
	int buckets;
	int count;
	struct keybag ** data;
};

uint32_t fnv_hash(uint8_t * key) {
	int i;
	uint32_t hash = 2166136261; // offset_basis
	for(i = 0; i < 32; i++) {
		hash ^= key[i];
		hash *= 16777619; //fnv_prime
	}
	hash =(hash>>16) ^ (hash & 0xffff);

	return hash;
}

int rehash_keybags(struct keybaghash * o) {
	if(!(o->count > o->buckets && o->count < (0xffff)))
		return 0;

	int kiter;
	int newsize = ((o->buckets + 1) << 2) - 1;

	struct keybag ** newdata = calloc(newsize + 1, sizeof(struct keybag*));
	if(newdata == NULL)
		return -ENOMEM;

	for(kiter = 0; kiter < o->buckets + 1; kiter++) {
		struct keybag * curkey = o->data[kiter], *savekey;
		while(curkey) {
			uint32_t hash = fnv_hash(curkey->key) & newsize;
			savekey = curkey->next;
			curkey->next = newdata[hash];
			newdata[hash] = curkey;
			curkey = savekey;
		}
	}

	free(o->data);
	o->buckets = newsize;
	o->data = newdata;
	return 0;
}

int read_keyfile(const char * path, struct keybaghash * o) {
	char * buf = NULL;
	size_t buflen = 0;
	ssize_t readcount;
	int i;

	FILE * fp = fopen(path, "r");
	if(fp == NULL)
		return errno;

	for(i = 0; i < o->buckets; i++) {
		while(o->data[i]) {
			struct keybag * n = o->data[i]->next;
			free(o->data[i]);
			o->data[i] = n;
		}
	}
	o->count = 0;

	while((readcount = getline(&buf, &buflen, fp)) != -1) {
		char * end = buf + readcount, *front = buf;
		buflen = buflen > readcount ? buflen : readcount;

		while(front < end && isspace(*front))
			front++;
		if(*front == '\0' || *front == '#')
			continue;

		while(end - 1 > front && isspace(*(end - 1)))
			end--;
		if(isspace(*end))
			*end = '\0';
		end -= 40;

		if(end < front)
			continue;

		struct keybag * nk = calloc(1, sizeof(struct keybag));

		if(zmq_z85_decode(nk->key, end) == NULL) {
			free(nk);
			continue;
		}

		uint32_t hashval = fnv_hash(nk->key) & o->buckets;

		nk->next = o->data[hashval];
		o->data[hashval] = nk;
		o->count++;

		if(rehash_keybags(o) != 0)
			return -ENOMEM;
	}

	fclose(fp);
	free(buf);
	return 0;
}

int send_zap_resp(zmq_msg_t * reqid, char * code, char * text,
	char *user, void * sock) {
	int i = 0;

	struct tosend {
		char * val;
		size_t msgsize;
	} msgs[] = {
		{ "1.0", 3 },
		{ zmq_msg_data(reqid), zmq_msg_size(reqid) },
		{ code, strlen(code) },
		{ text, strlen(text) },
		{ user, strlen(user) },
		{ "", 0 },
		{ NULL, 0 }
	};

	for(i = 0; msgs[i].val != NULL; i++) {
		int flags = ZMQ_SNDMORE, rc;
		if(msgs[i + 1].val == NULL)
			flags = 0;
		rc = zmq_send(sock, msgs[i].val, msgs[i].msgsize, flags);
		if(rc == -1) {
			if(errno == ETERM)
				return -ETERM;
		}
	}

	return 0;
}

void * zap_handler(void* zapsock) {
	struct keybaghash bag;
	bag.buckets = 63;
	bag.data = calloc(63, sizeof(struct keybag*));
	bag.count = 0;
	time_t last_refresh = 0;
	int keeprunning = 1, i;
	sigset_t sigset;

	sigfillset(&sigset);
	pthread_sigmask(SIG_SETMASK, &sigset, NULL);

	syslog(LOG_DEBUG, "Starting ZeroMQ Authentication Thread");

	for(;;) {
		time_t now = time(NULL);
		int rc;
		if(rc = now - last_refresh > keyfile_refresh_interval) {
			if((rc = read_keyfile(curve_knownhosts, &bag)) != 0)
				syslog(LOG_ERR, "Error reading clients file: %s", strerror(rc));
			last_refresh = now;
			syslog(LOG_DEBUG, "Read in key file for ZeroMQ Curve Auth");
		}

		zmq_msg_t reqid;
		char mech[32], creds[255];
		i = 0;

		zmq_msg_init(&reqid);
		for(i = 0; i < 7; i++) {
			zmq_msg_t curmsg;

			zmq_msg_init(&curmsg);
			rc = zmq_msg_recv(&curmsg, zapsock, 0);
			if(rc == -1) {
				if(errno == ETERM) {
					keeprunning = 0;
					break;
				}
				else
					break;
				syslog(LOG_DEBUG, "Error receiving auth packet");
			}

			if(i == 1) {
				size_t msglen = zmq_msg_size(&curmsg);
				zmq_msg_init_size(&reqid, msglen);
				memcpy(zmq_msg_data(&reqid), zmq_msg_data(&curmsg), msglen);
			}
			else if(i == 5)
				strncpy(mech, zmq_msg_data(&curmsg), zmq_msg_size(&curmsg));
			else if(i == 6)
				memcpy(creds, zmq_msg_data(&curmsg), zmq_msg_size(&curmsg));
			zmq_msg_close(&curmsg);
		}

		if(keeprunning == 0)
			break;
		else if(i < 7)
			continue;

		if(strcmp(mech, "CURVE") != 0) {
			rc = send_zap_resp(&reqid, "400",
				"Must use curve auth", "", zapsock);
			syslog(LOG_DEBUG, "Mechanism wasn't curve: %s", mech);
			goto cleanup;
		}

		uint32_t hashval = fnv_hash(creds);
		hashval &= bag.buckets;

		struct keybag * search = bag.data[hashval];

		while(search && memcmp(search->key, creds, 32) != 0)
			search = search->next;

		if(search == NULL) {
			rc = send_zap_resp(&reqid, "400",
				"No authorized key found", "", zapsock);
			syslog(LOG_DEBUG, "Client not found in ZeroMQ authorized keys file!");
			goto cleanup;
		}

		rc = send_zap_resp(&reqid, "200",
			"Authentication successful", "Authenticated User", zapsock);
		syslog(LOG_DEBUG, "Successfully authenticated client from authorized keys file!");
cleanup:
		zmq_msg_close(&reqid);
		if(rc == ETERM)
			break;
	}

	for(i = 0; i < bag.buckets; i++) {
		while(bag.data[i]) {
			struct keybag * n = bag.data[i]->next;
			free(bag.data[i]);
			bag.data[i] = n;
		}
	}

	free(bag.data);
	zmq_close(zapsock);
	return NULL;
}
#endif

int handle_startup(int which, void * obj) {
	struct nebstruct_process_struct *ps = (struct nebstruct_process_struct *)obj;
	time_t now = ps->timestamp.tv_sec;

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
						return NULL;
					}

					if(zmq_bind(zapsock, "inproc://zeromq.zap.01") != 0) {
						syslog(LOG_ERR, "Error binding to ZAP endpoint");
						return NULL;
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
			zmq_term(zmq_ctx);
			break;
	}
	return 0;
}

int nebmodule_init(int flags, char * localargs, nebmodule * lhandle) {
	json_error_t loaderr;
	handle = lhandle;

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

