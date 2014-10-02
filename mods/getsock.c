#include "config.h"
#include <zmq.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ICINGA
#include "icinga.h"
#else
#include "nagios.h"
#endif
#include "json.h"

extern void * zmq_ctx;
extern char * curve_publickey, *curve_privatekey;

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
		logit(NSLOG_CONFIG_ERROR, TRUE,
			"Invalid parameters for creating %s NagMQ socket", forwhat);
		return NULL;
	}

	if(!connect && !bind && !connect_array && !bind_array) {
		logit(NSLOG_CONFIG_ERROR, TRUE,
			"NagMQ socket for %s did not have any connections or binds defined",
			forwhat);
		return NULL;
	}

	void * sock = zmq_socket(zmq_ctx, type);
	if(sock == NULL) {
		logit(NSLOG_RUNTIME_ERROR, TRUE,
			"Error creating NagMQ socket for %s: %s",
			forwhat, zmq_strerror(errno));
		return NULL;
	}

#if ZMQ_VERSION_MAJOR == 2
	if(hwm > 0 &&
		zmq_setsockopt(sock, ZMQ_HWM, &hwm, sizeof(hwm)) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error setting HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}
#else
	if(sndhwm > 0 &&
		zmq_setsockopt(sock, ZMQ_SNDHWM, &sndhwm, sizeof(sndhwm)) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error setting send HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(rcvhwm > 0 &&
		zmq_setsockopt(sock, ZMQ_RCVHWM, &rcvhwm, sizeof(sndhwm)) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error setting receive HWM for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(backlog > 0 &&
		zmq_setsockopt(sock, ZMQ_BACKLOG, &backlog, sizeof(backlog)) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error setting connection backlog for %s: %s",
			forwhat, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	}

	if(maxmsgsize > 0 &&
		zmq_setsockopt(sock, ZMQ_MAXMSGSIZE, &maxmsgsize, sizeof(maxmsgsize)) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error setting maximum message size for %s: %s",
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
				logit(NSLOG_CONFIG_ERROR, TRUE,
					"NagMQ TCP accept filter %lu for %s is not a string", i, forwhat);
				zmq_close(sock);
				return NULL;
			}
			size_t flen = strlen(filter);
			if(zmq_setsockopt(sock, ZMQ_TCP_ACCEPT_FILTER, filter, flen) != 0) {
				logit(NSLOG_RUNTIME_ERROR, TRUE,
					"Error setting NagMQ TCP accept filter %s for %s: %s",
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
			logit(NSLOG_RUNTIME_ERROR, TRUE, "Error setting NagMQ secret key for %s %s %d %s",
				forwhat, curve_privatekey, strlen(curve_privatekey), zmq_strerror(errno));
			zmq_close(sock);
			return NULL;
		}
		rc = zmq_setsockopt(sock, ZMQ_CURVE_PUBLICKEY,
			curve_privatekey, strlen(curve_publickey));
		if(rc == -1) {
			logit(NSLOG_RUNTIME_ERROR, TRUE, "Error setting NagMQ public key for %s %s %s",
				forwhat, curve_privatekey, zmq_strerror(errno));
			zmq_close(sock);
			return NULL;
		}
		zmq_setsockopt(sock, ZMQ_CURVE_SERVER, &yes, sizeof(int));
		log_debug_info(DEBUGL_CONFIG, DEBUGV_BASIC, "Set up curve security in NagMQ\n");
	}
#endif

	if(connect && zmq_connect(sock, connect) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error connecting %s to %s: %s",
			forwhat, connect, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	} else if(connect_array && !connect) {
		size_t i;
		for(i = 0; i < json_array_size(connect_array); i++) {
			json_t * target = json_array_get(connect_array, i);
			if(zmq_connect(sock, json_string_value(target)) != 0) {
				logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error connecting %s to %s: %s",
					forwhat, json_string_value(target), zmq_strerror(errno));
				zmq_close(sock);
				return NULL;
			}
		}
	}

	if(bind && zmq_bind(sock, bind) != 0) {
		logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error binding %s to %s: %s",
			forwhat, bind, zmq_strerror(errno));
		zmq_close(sock);
		return NULL;
	} else if(bind_array && !bind) {
		size_t i;
		for(i = 0; i < json_array_size(bind_array); i++) {
			json_t * target = json_array_get(bind_array, i);
			if(zmq_bind(sock, json_string_value(target)) != 0) {
				logit(NSLOG_RUNTIME_ERROR, TRUE, "NagMQ error binding %s to %s: %s",
					forwhat, json_string_value(target), zmq_strerror(errno));
				zmq_close(sock);
				return NULL;
			}
		}
	}

	return sock;
}
