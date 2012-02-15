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
#include "json.h"

int setup_zmq(char * args, int type, 
	void ** ctxo, void ** socko) {
	void * ctx = NULL, *sock = NULL;
	char * bindto = NULL, *connectto = NULL;
	int numthreads = 1, hwm = 0;
	char * name, *val;

	while(*args != '\0') {
		name = args;
		while(*args != ',' && *args != '\0') {
			if(*args == '=') {
				*args = '\0';
				val = args + 1;
			}
			args++;
		}
		*args = '\0';
		if(strcmp(name, "bind") == 0)
			bindto = val;
		else if(strcmp(name, "connect") == 0)
			connectto = val;
		else if(strcmp(name, "iothreads") == 0)
			numthreads = atoi(val);
		else if(strcmp(name, "hwm") == 0)
			hwm = atoi(val);
	}

	if(!connectto && !bindto) {
		syslog(LOG_ERR, "Neither a connection or bind url was supplied to ZMQ");
		return -1;
	}

	ctx = zmq_init(numthreads);
	if(ctx == NULL) {
		syslog(LOG_ERR, "Error initialzing ZMQ context: %s",
			zmq_strerror(errno));
		return -1;
	}

	sock = zmq_socket(ctx, type);
	if(sock == NULL) {
		syslog(LOG_ERR, "Error creating ZMQ socket: %s",
			zmq_strerror(errno));
		zmq_term(ctx);
		return -1;
	}

	if(hwm > 0 && zmq_setsockopt(sock, ZMQ_HWM, &hwm, sizeof(hwm)) != 0) {
		syslog(LOG_ERR, "Error setting HWM to %d: %s",
			hwm, zmq_strerror(errno));
		zmq_close(sock);
		zmq_term(ctx);
		return -1;
	}

	if(connectto && zmq_connect(sock, connectto) < 0) {
		syslog(LOG_ERR, "Error connecting socket to %s: %s",
			connectto, zmq_strerror(errno));
		zmq_close(sock);
		zmq_term(ctx);
		return -1;	
	}

	if(bindto && zmq_bind(sock, bindto) < 0) {
		syslog(LOG_ERR, "Error binding socket to %s: %s",
			bindto, zmq_strerror(errno));
		zmq_close(sock);
		zmq_term(ctx);
		return -1;
	}
	*ctxo = ctx;
	*socko = sock;
	return 0;
}

