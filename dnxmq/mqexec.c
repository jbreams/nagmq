#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdint.h>
#include <fcntl.h>
#include <pwd.h>
#include <libev/ev.h>
#include <zmq.h>
#include <jansson.h>
#include <syslog.h>

#ifndef MAX_PLUGIN_OUTPUT_LENGTH
#define MAX_PLUGIN_OUTPUT_LENGTH 8192
#endif

void * zmqctx;
// Worker Sockets
void * pullsock;
void * pushsock;
// Broker Sockets
void * uppush = NULL;
void * uppub = NULL;
void * uppull = NULL;
void * upsub = NULL;
void * downpush = NULL;
void * downpull = NULL;
ev_io eupull, eusub, edpull;
int usesyslog = 0, verbose = 0;

struct child_job {
	json_t * input;
	char buffer[MAX_PLUGIN_OUTPUT_LENGTH];
	size_t bufused;
	struct timeval start;
	int service;
	int timeout;
	ev_io io;
	ev_child child;
	ev_timer timer;
};

#define ERR 2
#define DEBUG 1
#define INFO 0
void logit(int level, char * fmt, ...) {
	int err;
	va_list ap;

	if(level == 0)
		err = LOG_INFO;
	else if(level == 1) {
		if(verbose == 0)
			return;
		err = LOG_DEBUG;
	}
	else
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

void free_cb(void * data, void * hint) {
	free(data);
}

void obj_for_ending(struct child_job * j, const char * output,
	int return_code, int exited_ok) {
	zmq_msg_t outmsg;
	const char * keys[] = { "host_name", "service_description",
		"check_options", "scheduled_check", "reschedule_check",
		"latency", "early_timeout", "check_type", NULL };
	struct timeval finish;
	int i;

	if(j->start.tv_sec == 0)
		gettimeofday(&j->start, NULL);
	gettimeofday(&finish, NULL);
	json_t * jout = json_pack(
		"{ s:s s:i s:i s:{ s:i s:i } s:{ s:i s:i } s:s }",
		"output", output, "return_code", return_code,
		"exited_ok", exited_ok, "start_time", "tv_sec", j->start.tv_sec,
		"tv_usec", j->start.tv_usec, "finish_time", "tv_sec",
		finish.tv_sec, "tv_usec", finish.tv_usec, "type",
		j->service ? "service_check_processed":"host_check_processed");

	for(i = 0; keys[i] != NULL; i++) {
		json_t * val = json_object_get(j->input, keys[i]);
		if(val)
			json_object_set(jout, keys[i], val);
	}

	char * strout= json_dumps(jout, JSON_COMPACT);
	json_decref(jout);

	zmq_msg_init_data(&outmsg, strout, strlen(strout), free_cb, NULL);
	zmq_send(pushsock, &outmsg, 0);
	zmq_msg_close(&outmsg);
}

void child_io_cb(struct ev_loop * loop, ev_io * i, int event) {
	struct child_job * j = (struct child_job*)i->data;
	size_t r;

	do {
		r = read(i->fd, j->buffer + j->bufused,
			sizeof(j->buffer) - j->bufused);
		if(r > 0)
			j->bufused += r;
	} while(r > 0 && j->bufused < sizeof(j->buffer));
	if(j->bufused == sizeof(j->buffer))
		ev_io_stop(loop, i);
}

void child_timeout_cb(struct ev_loop * loop, ev_timer * t, int event) {
	struct child_job * j = (struct child_job*)t->data;
	ev_tstamp after = j->start.tv_sec - ev_now(loop) + j->timeout;
	if(after > 0) {
		ev_timer_set(t, after, 0);
		ev_timer_start(loop, t);
		return;
	}

	ev_timer_stop(loop, t);
	if(ev_is_active(&j->io)) {
		ev_io_stop(loop, &j->io);
		close(j->io.fd);
	}

	if(ev_is_active(&j->child)) {
		ev_child_stop(loop, &j->child);
		if(j->child.pid)
			kill(j->child.pid, SIGKILL);
	}

	obj_for_ending(j, "Check timed out", 4, 0);
	logit(DEBUG, "Child %d timed out. Sending timeout message upstream",
		j->child.pid);
	json_decref(j->input);
	free(j);
}

void child_end_cb(struct ev_loop * loop, ev_child * c, int event) {
	struct child_job * j = (struct child_job*)c->data;

	ev_child_stop(loop, c);
	if(ev_is_active(&j->io)) {
		child_io_cb(loop, &j->io, EV_READ);
		if(ev_is_active(&j->io))
			ev_io_stop(loop, &j->io);
		close(j->io.fd);
	}

	if(ev_is_active(&j->timer))
		ev_timer_stop(loop, &j->timer);

	if(!j->bufused)
		strcpy(j->buffer, "");

	obj_for_ending(j, j->buffer, WEXITSTATUS(c->rstatus), 1);
	logit(DEBUG, "Child %d ended with %d. Sending \"%s\" upstream",
		c->rpid, c->rstatus, j->buffer);
	json_decref(j->input);
	free(j);
}

void do_kickoff(struct ev_loop * loop, zmq_msg_t * inmsg) {
	json_t * input;
	struct child_job * j;
	char * type, *command_line;
	json_error_t err;
	int fds[2];
	pid_t pid;
	int rc, timeout = 0;

	input = json_loadb(zmq_msg_data(inmsg), zmq_msg_size(inmsg), 0, &err);
	zmq_msg_close(inmsg);
	if(input == NULL) {
		logit(ERR, "Error loading request from broker: %s (line %d col %d)",
			err.text, err.line, err.column);
		return;
	}

	if(json_unpack(input, "{ s:s s:s s?:i }",
		"type", &type, "command_line", &command_line,
		"timeout", &timeout) != 0) {
		json_decref(input);
		return;
	}
	logit(DEBUG, "Received job from upstream: %s %s",
		type, command_line);

	j = malloc(sizeof(struct child_job));
	memset(j, 0, sizeof(struct child_job));
	if(strcmp(type, "service_check_initiate") == 0)
		j->service = 1;
	else
		j->service = 0;
	j->input = input;

	if(pipe(fds) < 0) {
		logit(ERR, "Error creating pipe for %s: %s",
			command_line, strerror(errno));
		obj_for_ending(j, "Error creating pipe", 4, 0);
		free(j);
		json_decref(input);
		return;		
	};
	fcntl(fds[0], F_SETFL, O_NONBLOCK);

	ev_io_init(&j->io, child_io_cb, fds[0], EV_READ);
	j->io.data = j;
	ev_io_start(loop, &j->io);
	
	gettimeofday(&j->start, NULL);
	pid = fork();
	if(pid == 0) {
		char * argv[1024];
		int argc = 0;
		memset(argv, 0, sizeof(argv));
		char * lck = command_line, *save = lck;
		while(*lck) {
			if(*lck == ' ') {
				argv[argc++] = save;
				*(lck++) = '\0';
				while(*lck && *lck == ' ')
					lck++;
				save = lck;
			}
			else if(*lck == '\"') {
				save = ++lck;
				while(*lck && *lck != '\"' && *(lck - 1) != '\\')
					lck++;
				argv[argc++] = save;
				*(lck++) = '\0';
				save = lck;
			}
			else
				lck++;
		}
		if(*save)
		argv[argc++] = save;
		dup2(fds[1], fileno(stdout));
#ifdef TEST
		printf("Testing testing testing!\n");
		exit(0);
#else
		execv(command_line, argv);
		rc = errno;
		printf("Error executing %s: %m", command_line);
		exit(4);
#endif
	}
	else if(pid < 0) {
		logit(ERR, "Error forking for %s: %s",
			command_line, strerror(errno));
		obj_for_ending(j, "Error forking", 4, 0);
		json_decref(input);
		ev_io_stop(loop, &j->io);
		close(fds[1]);
		close(fds[0]);
		free(j);
		return;
	}
	close(fds[1]);

	if(timeout > 0) {
		ev_timer_init(&j->timer, child_timeout_cb, timeout, 0);
		j->timer.data = j;
		ev_timer_start(loop, &j->timer);
		j->timeout = timeout;
	}
	
	logit(DEBUG, "Kicked off %d", pid);
	ev_child_init(&j->child, child_end_cb, pid, 0);
	j->child.data = j;
	ev_child_start(loop, &j->child);
}

void recv_job_cb(struct ev_loop * loop, ev_io * i, int event) {
	uint32_t events = ZMQ_POLLIN;
	size_t evs = sizeof(events);

	while(zmq_getsockopt(pullsock, ZMQ_EVENTS, &events,
		&evs) == 0 && (events & ZMQ_POLLIN)) {
		zmq_msg_t inmsg;
		int64_t rcvmore = 0;
		size_t rms = sizeof(rcvmore);

		zmq_msg_init(&inmsg);
		if(zmq_recv(i->data, &inmsg, 0) != 0) {
			logit(ERR, "Error receiving message from broker %d", errno);
			continue;
		}

		zmq_getsockopt(i->data, ZMQ_RCVMORE, &rcvmore, &rms);
		if(rcvmore) {
			zmq_msg_close(&inmsg);
			if(zmq_recv(i->data, &inmsg, 0) != 0) {
				logit(ERR, "Error receiving message from broker %d", errno);
				continue;
			}
		}

		do_kickoff(loop, &inmsg);
	}
}

void recv_up_cb(struct ev_loop * loop, ev_io * io, int events) {
	uint32_t sockevents = 0;
	int64_t rcvmore = 0;
	size_t evs = sizeof(sockevents), rms = sizeof(rcvmore);
	void * extsock = io->data;
	zmq_msg_t inmsg;

	while(zmq_getsockopt(extsock, ZMQ_EVENTS,
		&sockevents, &evs) == 0 && sockevents & ZMQ_POLLIN) {
		int64_t rcvmore = 0;
		zmq_msg_init(&inmsg);
		if(zmq_recv(extsock, &inmsg, 0) != 0) {
			zmq_msg_close(&inmsg);
			return;
		}

		evs = sizeof(rcvmore);
		zmq_getsockopt(extsock, ZMQ_RCVMORE, &rcvmore, &rms);
		if(rcvmore) {
			zmq_msg_close(&inmsg);
			zmq_msg_init(&inmsg);
			if(zmq_recv(extsock, &inmsg, 0) != 0) {
				zmq_msg_close(&inmsg);
				return;
			}
		}

		zmq_send(downpush, &inmsg, 0);
		zmq_msg_close(&inmsg);
		logit(DEBUG, "Pushed message downstream");
	}
}

void recv_down_cb(struct ev_loop * loop, ev_io * io, int events) {
	uint32_t sockevents = 0;
	size_t evs = sizeof(sockevents);
	zmq_msg_t inmsg, pubmsg;

	while(zmq_getsockopt(downpull, ZMQ_EVENTS,
		&sockevents, &evs) == 0 && sockevents & ZMQ_POLLIN) {

		zmq_msg_init(&inmsg);
		if(zmq_recv(downpull, &inmsg, 0) != 0) {
			zmq_msg_close(&inmsg);
			continue;
		}

		if(uppush) {
			zmq_send(uppush, &inmsg, 0);
			logit(DEBUG, "Pushed message upstream");
		}
		if(uppub) {
			zmq_msg_copy(&pubmsg, &inmsg);
			zmq_send(uppub, &pubmsg, 0);
			logit(DEBUG, "Published message upstream");
			zmq_msg_close(&pubmsg);
		}
		zmq_msg_close(&inmsg);
	}
}

void parse_sock_directive(void * socket, json_t * arg, int bind) {
	int i;
	if(!arg)
		return;
	if(json_is_string(arg)) {
		if(bind)
			zmq_bind(socket, json_string_value(arg));
		else
			zmq_connect(socket, json_string_value(arg));
	} else if(json_is_object(arg)) {
		char * addr = NULL;
		json_t * subscribe = NULL;
		if(json_unpack(arg, "{s:s s?:b s?:o}", 
			"address", &addr, "bind", &bind, "subscribe",
			&subscribe) != 0)
			return;
		if(bind)
			zmq_bind(socket, addr);
		else
			zmq_connect(socket, addr);
		logit(DEBUG, "Socket object def %s (bind: %d)",
			addr, bind);

		if(subscribe) {
			int type;
			size_t ts = sizeof(type);
			zmq_getsockopt(socket, ZMQ_TYPE, &type, &ts);
			if(type != ZMQ_SUB)
				return;
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

int getfd(void * socket) {
	int fd;
	size_t fds = sizeof(fd);
	zmq_getsockopt(socket, ZMQ_FD, &fd, &fds);
	return fd;
}

int start_broker(struct ev_loop * loop, json_t * config) {
	json_t * uppushc = NULL, *uppubc = NULL, *upsubc = NULL,
	*downpushc, *downpullc, *uppullc = NULL;
	json_error_t err;
	if(json_unpack_ex(config, &err, 0, "{s{s:os:o}s{s?:o s?:o s?:o s?:o *}}",
		"downstream", "push", &downpushc, "pull", &downpullc,
		"upstream", "subscribe", &upsubc, "publish", &uppubc,
		"push", &uppushc, "pull", &uppullc) != 0) {
		logit(ERR, "Error parsing broker configuration %s (line %d col %d)",
			err.text, err.line, err.column);
		return -1;
	}

	if(!uppubc && !uppushc) {
		logit(ERR, "Must supply an upstream publisher or pipeline");
		return -1;
	}
	
	if(!upsubc && !uppullc) {
		logit(ERR, "Must supply an upstream subscriber or pipeline");
		return -1;
	}

	downpush = zmq_socket(zmqctx, ZMQ_PUSH);
	parse_sock_directive(downpush, downpushc, 1);
	logit(DEBUG, "Setup downstream pusher");
	downpull = zmq_socket(zmqctx, ZMQ_PULL);
	parse_sock_directive(downpull, downpullc, 1);
	ev_io_init(&edpull, recv_down_cb, getfd(downpull), EV_READ);
	ev_io_start(loop, &edpull);
	logit(DEBUG, "Setup downstream puller");
	
	if(uppullc) {
		uppull = zmq_socket(zmqctx, ZMQ_PULL);
		parse_sock_directive(uppull, uppullc, 0);
		ev_io_init(&eupull, recv_up_cb, getfd(uppull), EV_READ);
		eupull.data = uppull;
		ev_io_start(loop, &eupull);
		logit(DEBUG, "Setup upstream puller");
	}
	if(upsubc) {
		upsub = zmq_socket(zmqctx, ZMQ_SUB);
		parse_sock_directive(upsub, upsubc, 0);
		ev_io_init(&eusub, recv_up_cb, getfd(upsub), EV_READ);
		eusub.data = upsub;
		ev_io_start(loop, &eusub);
		logit(DEBUG, "Setup upstream subscriber");
	}

	if(uppushc) {
		uppush = zmq_socket(zmqctx, ZMQ_PUSH);
		parse_sock_directive(uppush, uppushc, 0);
		logit(DEBUG, "Setup upstream pusher");
	}
	if(uppubc) {
		uppub = zmq_socket(zmqctx, ZMQ_PUB);
		parse_sock_directive(uppub, uppubc, 1);
		logit(DEBUG, "Setup upstream publisher");
	}
	return 0;
}

int main(int argc, char ** argv) {
	ev_io pullio;
	struct ev_loop  * loop;
	json_t * jobs, * results;
	int iothreads = 1;
	int pullfd = -1;
	size_t pullfds = sizeof(pullfd);
	json_t * config, *broker = NULL;
	json_error_t config_err;

	if(argc == 2) {
		logit(ERR, "Must supply path to nagmq config and process type.");
		exit(-1);
	}

	config = json_load_file(argv[1], JSON_DISABLE_EOF_CHECK, &config_err);
	if(config == NULL) {
		logit(ERR, "Error parsing config: %s: (line: %d column: %d)",
			config_err.text, config_err.line, config_err.column);
		exit(-1);
	}

	if(json_unpack(config, "{s:{s:os:os?:os?is?bs?b}}",
		"executor", "jobs", &jobs, "results", &results,
		"broker", &broker, "iothreads", &iothreads,
		"verbose", &verbose, "syslog", &usesyslog) != 0) {
		logit(ERR, "Error getting config");
		exit(-1);
	}

	zmqctx = zmq_init(iothreads);
	if(zmqctx == NULL)
		exit(-1);

	loop = ev_default_loop(0);
	if(strcmp(argv[2], "worker") == 0) {
		pushsock = zmq_socket(zmqctx, ZMQ_PUSH);
		if(pushsock == NULL) {
			logit(ERR, "Error creating results socket %d", errno);
			exit(-1);
		}
		parse_sock_directive(pushsock, results, 0);
		logit(DEBUG, "Setup worker push socket");

		pullsock = zmq_socket(zmqctx, ZMQ_PULL);
		if(pullsock == NULL) {
			logit(ERR, "Error creating jobs socket %d", errno);
			exit(-1);
		}
		parse_sock_directive(pullsock, jobs, 0);
		logit(DEBUG, "Setup worker pull sock");

		zmq_getsockopt(pullsock, ZMQ_FD, &pullfd, &pullfds);
		if(pullfd == -1) {
			logit(ERR, "Error getting fd for pullsock");
			exit(-1);
		}
		ev_io_init(&pullio, recv_job_cb, pullfd, EV_READ);
		pullio.data = pullsock;
		ev_io_start(loop, &pullio);
	} else if(strcmp(argv[2], "broker") == 0) {
		if(broker && start_broker(loop, broker) < 0)
			exit(-1);
	} else {
		logit(ERR, "Must specify type as either a broker or a worker");
		exit(-1);
	}

	json_decref(config);
	logit(INFO, "Starting DNXMQ event loop");
	ev_run(loop, 0);
	logit(INFO, "DNXMQ event loop terminated");

	zmq_close(pullsock);
	zmq_close(pushsock);
	if(uppush)
		zmq_close(uppush);
	if(uppub)
		zmq_close(uppub);
	if(uppull)
		zmq_close(uppull);
	if(upsub)
		zmq_close(upsub);
	if(downpush)
		zmq_close(downpush);
	if(downpull)
		zmq_close(downpull);
	zmq_term(zmqctx);
	return 0;
}
