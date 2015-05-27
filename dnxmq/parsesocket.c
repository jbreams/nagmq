#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include "mqexec.h"

extern char * curve_private, *curve_public, *curve_server;
extern int reconnect_ivl, reconnect_ivl_max;
extern int config_heartbeat_interval, config_heartbeat_timeout;

void parse_sock_directive(void * socket, json_t * arg, int bind) {
	int i, rc;
	if(!arg)
		return;
	if(json_is_string(arg)) {
#if ZMQ_VERSION_MAJOR > 3
		if(curve_private) {
			zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY,
				curve_private, strlen(curve_private));
			zmq_setsockopt(socket, ZMQ_CURVE_PUBLICKEY,
				curve_public, strlen(curve_public));
			zmq_setsockopt(socket, ZMQ_CURVE_SERVERKEY,
				curve_server, strlen(curve_server));
		}
#endif
		zmq_setsockopt(socket, ZMQ_RECONNECT_IVL,
			&reconnect_ivl, sizeof(reconnect_ivl));
		zmq_setsockopt(socket, ZMQ_RECONNECT_IVL_MAX,
			&reconnect_ivl_max, sizeof(reconnect_ivl_max));

        if(config_heartbeat_interval > 0) {
#ifdef ZMQ_HEARTBEAT_TIMEOUT
            zmq_setsockopt(socket, ZMQ_HEARTBEAT_IVL,
                &config_heartbeat_interval, sizeof(config_heartbeat_interval));
            if(config_heartbeat_timeout < 0)
                config_heartbeat_timeout = config_heartbeat_interval;
            zmq_setsockopt(socket, ZMQ_HEARTBEAT_TIMEOUT,
                &config_heartbeat_timeout, sizeof(config_heartbeat_timeout));
#else
            logit(ERR, "Heartbeat was configured, but is not available in this build of mqexec");
#endif
        }

		if(bind)
			rc = zmq_bind(socket, json_string_value(arg));
		else
			rc = zmq_connect(socket, json_string_value(arg));
		if(rc == -1) {
			logit(ERR, "Error %s to %s: %s",
				bind ? "binding" : "connecting",
				json_string_value(arg), zmq_strerror(errno));
			exit(1);
		}
	} else if(json_is_object(arg)) {
		char * addr = NULL;
		int sndtimeo = -1, rcvtimeo = -1;
		json_t * subscribe = NULL;
		if(json_unpack(arg, "{s:s s?:b s?:o s?i s?i}",
			"address", &addr,
			"bind", &bind,
			"subscribe",&subscribe,
			"sndtimeo", &sndtimeo,
			"rcvtimeo", &rcvtimeo) != 0)
			return;

#if ZMQ_VERSION_MAJOR > 3
		if(curve_private) {
			zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY,
				curve_private, strlen(curve_private));
			zmq_setsockopt(socket, ZMQ_CURVE_PUBLICKEY,
				curve_public, strlen(curve_public));
			zmq_setsockopt(socket, ZMQ_CURVE_SERVERKEY,
				curve_server, strlen(curve_server));
		}
#endif

		zmq_setsockopt(socket, ZMQ_RECONNECT_IVL,
			&reconnect_ivl, sizeof(reconnect_ivl));
		zmq_setsockopt(socket, ZMQ_RECONNECT_IVL_MAX,
			&reconnect_ivl_max, sizeof(reconnect_ivl_max));
		zmq_setsockopt(socket, ZMQ_SNDTIMEO,
			&sndtimeo, sizeof(sndtimeo));
		zmq_setsockopt(socket, ZMQ_RCVTIMEO,
			&rcvtimeo, sizeof(rcvtimeo));

        if(config_heartbeat_interval > 0) {
#ifdef ZMQ_HEARTBEAT_TIMEOUT
            zmq_setsockopt(socket, ZMQ_HEARTBEAT_IVL,
                &config_heartbeat_interval, sizeof(config_heartbeat_interval));
            if(config_heartbeat_timeout < 0)
                config_heartbeat_timeout = config_heartbeat_interval;
            zmq_setsockopt(socket, ZMQ_HEARTBEAT_TIMEOUT,
                &config_heartbeat_timeout, sizeof(config_heartbeat_timeout));
#else
            logit(ERR, "Heartbeat was configured, but is not available in this build of mqexec");
#endif
        }

		if(bind)
			rc = zmq_bind(socket, addr);
		else
			rc = zmq_connect(socket, addr);
		if(rc == -1) {
			logit(ERR, "Error %s to %s: %s",
				bind ? "binding" : "connecting",
				json_string_value(arg), zmq_strerror(errno));
			exit(1);
		}
		logit(DEBUG, "Socket object def %s (bind: %d)",
			addr, bind);

		if(subscribe) {
			int opt;
			size_t optsize = sizeof(opt);
			zmq_getsockopt(socket, ZMQ_TYPE, &opt, &optsize);
			if(opt != ZMQ_SUB)
				return;
			opt = 1;
#if ZMQ_VERSION < 30300
			zmq_setsockopt(socket, ZMQ_DELAY_ATTACH_ON_CONNECT, &opt, &optsize);
#else
			zmq_setsockopt(socket, ZMQ_IMMEDIATE, &opt, optsize);
#endif
			if(json_is_string(subscribe)) {
				const char * opt = json_string_value(subscribe);
				zmq_setsockopt(socket, ZMQ_SUBSCRIBE, opt, strlen(opt));
				logit(DEBUG, "Subscribing to %s", opt);
			}
			else if(json_is_array(subscribe)) {
				for(i = 0; i < json_array_size(subscribe); i++) {
					json_t * tmp = json_array_get(subscribe, i);
					const char * opt = json_string_value(tmp);
					zmq_setsockopt(socket, ZMQ_SUBSCRIBE,
						opt, strlen(opt));
					logit(DEBUG, "Subscribing to %s", opt);
				}
			}
		}
	} else if(json_is_array(arg)) {
		for(i = 0; i < json_array_size(arg); i++) {
			json_t * tmp = json_array_get(arg, i);
			parse_sock_directive(socket, tmp, bind);
		}
	}
}
