#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>
#include <jansson.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>

void * zmqctx;
int usesyslog = 0, verbose = 0;
volatile sig_atomic_t keeprunning = 1;
volatile sig_atomic_t reload = 0;

#define WARN 3
#define ERR 2
#define DEBUG 1
#define INFO 0
void logit(int level, char * fmt, ...) {
	int err;
	va_list ap;

	if(level == INFO)
		err = LOG_INFO;
	else if(level == DEBUG) {
		if(verbose == 0)
			return;
		err = LOG_DEBUG;
	}
	else if(level == WARN)
		err = LOG_WARNING;
	else if(level == ERR);
		err = LOG_ERR;
	va_start(ap, fmt);
	if(usesyslog)
		vsyslog(err, fmt, ap);
	else {
		vfprintf(stderr, fmt, ap); 
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

int parse_connect(void * sock, json_t * val, int bind, json_t * subscribe) {
	size_t i;
	if(json_is_string(val)) {
		int rc;
		const char * addr = json_string_value(val);
		if(bind)
			rc = zmq_bind(sock, addr);
		else
			rc = zmq_connect(sock, addr);
		if(rc != 0) {
			logit(ERR, "Error binding/connecting to %s: %s",
				addr, zmq_strerror(errno));
			return -1;
		}

		if(subscribe) {
			if(json_is_string(subscribe)) {
				const char * opt = json_string_value(subscribe);
				zmq_setsockopt(sock, ZMQ_SUBSCRIBE, opt, strlen(opt));
				logit(DEBUG, "Subscribing to %s", opt);
			}
			else if(json_is_array(subscribe)) {
				for(i = 0; i < json_array_size(subscribe); i++) {
					json_t * tmp = json_array_get(subscribe, i);
					const char * opt = json_string_value(tmp);
					zmq_setsockopt(sock, ZMQ_SUBSCRIBE,
						opt, strlen(opt));
					logit(DEBUG, "Subscribing to %s", opt);
				}
			}
		}
	} else if(json_is_array(val)) {
		size_t i, arraysize = json_array_size(val);
		for(i = 0; i < arraysize; i++) {
			json_t * curval = json_array_get(val, i);
			if(parse_connect(sock, curval, bind, subscribe) < 0)
				return -1;
		}
		return 0;
	}
	return 0;
}

void parse_sock_directive(json_t * arg, zmq_pollitem_t * pollable, int * noblock) {
	int ntype = -1;
	char *type;
	int64_t hwm = 0, swap = 0, affinity = 0;
	json_t * subscribe = NULL, *connect = NULL, *bind = NULL;
	void * sock;
	if(json_unpack(arg, "{s:s s?:o s?:o s?:o s?i s?i s?i}", 
		"type", &type, "connect", &connect, "bind", &bind,
		"subscribe", &subscribe, "hwm", &hwm, "swap", &swap,
		"affinity", &affinity, "noblock", noblock) != 0)
		return;
	if(strcasecmp(type, "dealer") == 0)
		ntype = ZMQ_DEALER;
	else if(strcasecmp(type, "router") == 0)
		ntype = ZMQ_ROUTER;
	else if(strcasecmp(type, "pub") == 0)
		ntype = ZMQ_PUB;
	else if(strcasecmp(type, "sub") == 0)
		ntype = ZMQ_SUB;
	else if(strcasecmp(type, "pull") == 0)
		ntype = ZMQ_PULL;
	else if(strcasecmp(type, "push") == 0)
		ntype = ZMQ_PUSH;

	if(ntype == -1) {
		logit(ERR, "Invalid socket type: %s", type);
		exit(1);
	}
	sock = zmq_socket(zmqctx, ntype);
	if(sock == NULL) {
		logit(ERR, "Error creating socket: %s", zmq_strerror(errno));
		exit(1);
	}

	if(!bind && !connect) {
		logit(ERR, "Must supply either a bind or a connect when defining socket");
		exit(1);
	}

	if(ntype != ZMQ_SUB)
		subscribe = NULL;

	if(bind && parse_connect(sock, bind, 1, subscribe) < 0)
		exit(1);
	
	if(connect && parse_connect(sock, connect, 0, subscribe) < 0)
		exit(1);
		
	zmq_setsockopt(sock, ZMQ_HWM, &hwm, sizeof(hwm));
	zmq_setsockopt(sock, ZMQ_SWAP, &swap, sizeof(swap));
	zmq_setsockopt(sock, ZMQ_AFFINITY, &affinity, sizeof(affinity));

	pollable->socket = sock;
	pollable->events = 0;
	switch(ntype) {
		case ZMQ_ROUTER:
		case ZMQ_DEALER:
		case ZMQ_SUB:
		case ZMQ_PULL:
			pollable->events = ZMQ_POLLIN;
			break;
	}
}

void do_forward(void * in, void *out, void *mon, int noblock, int monnoblock) {
	zmq_msg_t tmpmsg;
	int rc;
	int64_t rcvmore;
	size_t size = sizeof(rcvmore);
	int flags = 0;

	zmq_msg_init(&tmpmsg);
	if(zmq_recv(in, &tmpmsg, 0) != 0) {
		rc = errno;
		zmq_msg_close(&tmpmsg);
		logit(WARN, "Error receiving message: %s", zmq_strerror(rc));
		return;
	}

	zmq_getsockopt(in, ZMQ_RCVMORE, &rcvmore, &size);
	if(mon) {
		flags = (rcvmore ? ZMQ_SNDMORE : 0) | (monnoblock ? ZMQ_NOBLOCK : 0);
		zmq_msg_t monmsg;
		zmq_msg_init(&monmsg);
		zmq_msg_copy(&monmsg, &tmpmsg);
		zmq_send(mon, &monmsg, flags);
		zmq_msg_close(&monmsg);
	}
	flags = (rcvmore ? ZMQ_SNDMORE : 0) | (noblock ? ZMQ_NOBLOCK : 0);
	zmq_send(out, &tmpmsg, flags);
	zmq_msg_close(&tmpmsg);
}

void handle_kill(int signum) {
	keeprunning = 0;
}

void * broker_loop(void * param) {
	json_t * devarray = (json_t*)param;
	zmq_pollitem_t * pollables;
	size_t ndevices;
	size_t i = 0, x = 0, rc;

	struct device {
		void * frontend;
		void * backend;
		void * monitor;
		zmq_pollitem_t * frontpoll;
		zmq_pollitem_t * backpoll;
		int frontnoblock;
		int backnoblock;
		int monnoblock;
	} * devices = NULL;

	if(!json_is_array(devarray)) {
		logit(ERR, "Device array is not an array!");
		exit(1);
	}

	// Allocate one poll item for the frontend, backend, and monitor sockets
	// of each device
	ndevices = json_array_size(devarray);
	devices = malloc(sizeof(struct device) * ndevices);
	memset(devices, 0, sizeof(struct device) * ndevices);

	for(i = 0; i < ndevices; i++) {
		json_t * device = json_array_get(devarray, i);
		json_t * frontend, *backend, *monitor = NULL;
		if(json_unpack(device, "{so so s?o}",
			"frontend", &frontend, "backend", &backend,
			"monitor", &monitor) != 0) {
			logit(ERR, "Error unpacking device %d", i);
			exit(1);
		}
		zmq_pollitem_t pollitem;
		parse_sock_directive(frontend, &pollitem, &devices[i].frontnoblock);
		devices[i].frontend = pollitem.socket;
		if(pollitem.events == ZMQ_POLLIN) {
			// For now these pointers are used as boolean
			// values - they'll be swapped with real pointers
			// in the next step
			devices[i].frontpoll = (void*)1;
			x++;
		}
		parse_sock_directive(backend, &pollitem, &devices[i].backnoblock);
		devices[i].backend = pollitem.socket;
		if(pollitem.events == ZMQ_POLLIN) {
			devices[i].backpoll = (void*)1;
			x++;
		}
		if(monitor) {
			parse_sock_directive(monitor, &pollitem, &devices[i].monnoblock);
			devices[i].monitor = pollitem.socket;
		}
	}

	pollables = malloc(sizeof(zmq_pollitem_t) * x);
	memset(pollables, 0, sizeof(zmq_pollitem_t) * x);
	x = 0;
	for(i = 0; i < ndevices; i++) {
		if(devices[i].frontpoll) {
			pollables[x].socket = devices[i].frontend;
			pollables[x].events = ZMQ_POLLIN;
			devices[i].frontpoll = &pollables[x++];
		}
		if(devices[i].backpoll) {
			pollables[x].socket = devices[i].backend;
			pollables[x].events = ZMQ_POLLIN;
			devices[i].backpoll = &pollables[x++];
		}
	}

	json_decref(devarray);

	do {
		rc = zmq_poll(pollables, x, -1);
		if(rc < 0) {
			rc = errno;
			if(rc == ETERM)
				break;
			logit(WARN, "Received error from poll: %s",
				zmq_strerror(rc));
		}
		if(rc < 1)
			continue;

		size_t i;
		for(i = 0; i < ndevices; i++) {
			if(devices[i].frontpoll && devices[i].frontpoll->revents & ZMQ_POLLIN) {
				logit(DEBUG, "Received message from frontend for device %d", i);
				do_forward(
					devices[i].frontend,
					devices[i].backend,
					devices[i].monitor,
					devices[i].backnoblock,
					devices[i].monnoblock);
			}
			if(devices[i].backpoll && devices[i].backpoll->revents & ZMQ_POLLIN) {
				logit(DEBUG, "Received message from backend for device %d", i);
				do_forward(
					devices[i].backend,
					devices[i].frontend,
					devices[i].monitor,
					devices[i].frontnoblock,
					devices[i].monnoblock);
			}
		}
	} while(keeprunning);

	for(i = 0; i < ndevices; i++) {
		if(devices[i].frontend)
			zmq_close(devices[i].frontend);
		if(devices[i].backend)
			zmq_close(devices[i].backend);
		if(devices[i].monitor)
			zmq_close(devices[i].monitor);
	}
	free(pollables);
	free(devices);
	return 0;
}

int main(int argc, char ** argv) {
	json_error_t config_err;
	json_t * config, *confarray = NULL;
	int rc, daemonize = 0, iothreads = 1;
	char ch, * configname = "devices";
	pthread_t * threads = NULL;

	while((ch = getopt(argc, argv, "vsdc:")) != -1) {
		switch(ch) {
			case 'v':
				verbose = 1;
				break;
			case 's':
				usesyslog = 1;
				break;
			case 'd':
				daemonize = 1;
				break;
			case 'h':
				printf("%s [-dsvh] [-c name] {pathtoconfig}\n"
					"\t-d\tDaemonize\n"
					"\t-s\tUse syslog for logging\n"
					"\t-v\tVerbose logging\n"
					"\t-h\tPrint this message\n"
					"\t-c name\tSpecify the conf object to use\n", argv[0]);
				break;
			case 'c':
				configname = optarg;
				break;
		}
	}
	if(daemonize)
		usesyslog = 1;
	
	argc -= optind;
	argv += optind;
	if(argc < 1) {
		logit(ERR, "Must supply path to broker config!");
		exit(1);
	}

	config = json_load_file(argv[0], JSON_DISABLE_EOF_CHECK, &config_err);
	if(config == NULL) {
		logit(ERR, "Error parsing config: %s: (line: %d column: %d)",
			config_err.text, config_err.line, config_err.column);
		exit(1);
	}

	if(json_unpack(config, "{s?:i s:O}", "iothreads", &iothreads,
		configname, &confarray) != 0) {
		logit(ERR, "Error getting config while setting up context");
		exit(1);
	}
	json_decref(config);

	if(!json_is_array(confarray) || json_array_size(confarray) < 1) {
		logit(ERR, "Configuration array is invalid!");
		exit(1);
	}

	if(daemonize && daemon(0, 0) < 0) {
		logit(ERR, "Error daemonizing: %s", strerror(errno));
		exit(1);
	}

	zmqctx = zmq_init(iothreads);
	if(zmqctx == NULL) {
		logit(ERR, "Error creating ZMQ context: %s", zmq_strerror(errno));
		exit(1);
	}

	struct sigaction killaction, oldaction;
	killaction.sa_handler = handle_kill;
	sigemptyset(&killaction.sa_mask);
	killaction.sa_flags = 0;

	sigaction(SIGTERM, NULL, &oldaction);
	if(oldaction.sa_handler != SIG_IGN)
		sigaction(SIGTERM, &killaction, NULL);
	sigaction(SIGINT, NULL, &oldaction);
	if(oldaction.sa_handler != SIG_IGN)
		sigaction(SIGINT, &killaction, NULL);

	if(!json_is_array(json_array_get(confarray, 0)))
		broker_loop(confarray);
	else {
		size_t i, nbrokers = json_array_size(confarray);
		threads = malloc(sizeof(pthread_t) * (nbrokers - 1));
		memset(threads, 0, sizeof(pthread_t) * (nbrokers - 1));
		for(i = 1; i < nbrokers; i++) {
			json_t * obj = json_copy(json_array_get(confarray, i));
			pthread_create(&threads[i - 1], NULL, broker_loop, obj);
		}
		json_t *firstobj = json_copy(json_array_get(confarray, 0));
		json_decref(confarray);
		broker_loop(firstobj);

		for(i =0; i < nbrokers - 1; i++)
			pthread_join(&threads[i]);
	}

	zmq_term(zmqctx);
	return 0;
}
