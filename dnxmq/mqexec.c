#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdint.h>
#include <fcntl.h>
#include <pwd.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>
#include <time.h>
#include "mqexec.h"

void * zmqctx;
// Worker Sockets
int pullsock_type = ZMQ_PULL;
void * pullsock = NULL;
void * pushsock = NULL;
// Broker Sockets
int usesyslog = 0, verbose = 0;
char myfqdn[255];
char mynodename[255];
uint32_t runningjobs = 0;
ev_io pullio;
char * rootpath = NULL, *unprivpath = NULL;
size_t rootpathlen = 0, unprivpathlen = 0;
uid_t runas = 0;
#if ZMQ_VERSION_MAJOR > 3
char * curve_private = NULL, *curve_public = NULL, *curve_server = NULL;
#endif
#if ZMQ_VERSION_MAJOR >= 3
ev_io pullmonio, pushmonio;
#endif
int reconnect_ivl = 1000, reconnect_ivl_max = 0;

// For reconnecting sockets after error
json_t * pullsockdef = NULL, *pushsockdef = NULL;
int pull_connected = 0, push_connected = 0;

void logit(int level, char * fmt, ...) {
	int err;
	va_list ap;
	char * levelstr;

	if(level == 0) {
		err = LOG_INFO;
		levelstr = "INFO";
	}
	else if(level == 1) {
		if(verbose == 0)
			return;
		err = LOG_DEBUG;
		levelstr = "DEBUG";
	}
	else {
		err = LOG_ERR;
		levelstr = "ERROR";
	}
	va_start(ap, fmt);
	if(usesyslog)
		vsyslog(err, fmt, ap);
	else {
		char datebuf[26];
		time_t now = time(NULL);
		ctime_r(&now, datebuf);
		datebuf[24] = '\0';

		fprintf(stderr, "%s %s: ", datebuf, levelstr);
		vfprintf(stderr, fmt, ap); 
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

void free_cb(void * data, void * hint) {
	free(data);
}

void obj_for_ending(struct child_job * j, const char * output,
	int return_code, int early_timeout, int exited_ok) {
	zmq_msg_t outmsg;
	const char * keys[] = { "host_name", "service_description",
		"check_options", "scheduled_check", "reschedule_check",
		"early_timeout", "check_type", NULL };
	struct timeval finish;
	int i, rc, retry_count = 0;

	if(j->start.tv_sec == 0)
		gettimeofday(&j->start, NULL);
	gettimeofday(&finish, NULL);
	json_t * jout = json_pack(
		"{ s:s s:i s:i s:i s:{ s:i s:i } s:{ s:i s:i } s:s s:f }",
		"output", output, "return_code", return_code,
		"exited_ok", exited_ok, "early_timeout", early_timeout,
		"start_time", "tv_sec", j->start.tv_sec,
		"tv_usec", j->start.tv_usec, "finish_time", "tv_sec",
		finish.tv_sec, "tv_usec", finish.tv_usec, "type",
		j->service ? "service_check_processed":"host_check_processed",
		"latency", j->latency);

	for(i = 0; keys[i] != NULL; i++) {
		json_t * val = json_object_get(j->input, keys[i]);
		if(val)
			json_object_set(jout, keys[i], val);
	}

	logit(DEBUG, "Sending result for %s %s: %s %i", j->host_name,
		j->service_description, output, return_code);
	char * strout= json_dumps(jout, JSON_COMPACT);
	json_decref(jout);
	zmq_msg_init_data(&outmsg, strout, strlen(strout), free_cb, NULL);

	// This loop will terminate based on whether the send was successful
	// It's just here to make sure signals can't drop check results.
	while(1) {
		if((rc = zmq_msg_send(&outmsg, pushsock, 0) == -1)) {
			// We get lots of signals because we're waiting on tons of children
			// best to just try again.
			if(errno == EINTR)
				continue;

			// We don't need to log anything for ETERM, because it's a normal
			// event that means "just quit now"
			if(errno != ETERM)
				logit(ERR, "Error sending message: %s", zmq_strerror(errno));
			break;
		}

		// If there was no error, exit the loop!
		break;
	}
	zmq_msg_close(&outmsg);
}

void child_io_cb(struct ev_loop * loop, ev_io * i, int event) {
	struct child_job * j = (struct child_job*)i->data;
	ssize_t r;

	do {
		r = read(i->fd, j->buffer + j->bufused,
			sizeof(j->buffer) - j->bufused - 1);
		if(r > 0)
			j->bufused += r;
	} while(r > 0 && j->bufused < sizeof(j->buffer) - 1);

	// If we've filled up the check result buffer, just stop reading from
	// the child.
	if(j->bufused == sizeof(j->buffer) - 1)
		ev_io_stop(loop, i);
}

void child_timeout_cb(struct ev_loop * loop, ev_timer * t, int event) {
	struct child_job * j = (struct child_job*)t->data;
	ev_tstamp after = (ev_now(loop) - j->start.tv_sec);
	if(after < j->timeout) {
		ev_timer_set(t, j->timeout - after, 0);
		ev_timer_start(loop, t);
		return;
	} else
		ev_timer_stop(loop, t);
	ev_io_stop(loop, &j->io);
	close(j->io.fd);

	// If the child is in our list of children, kill it.
	// This will also remove the child from the list of children.
	if(get_child(j->pid)) {
		kill(j->pid, SIGTERM);
	}

	if(j->service >= 0) {
		obj_for_ending(j, "Check timed out", 3, 1, 1);
		logit(DEBUG, "Child %d timed out. Sending timeout message upstream",
			j->pid);
	} else
		logit(DEBUG, "Non-check child %d timed out. Output so far: %s",
			j->pid, j->buffer);

	json_decref(j->input);
	free(j);
	if(--runningjobs == 0 && !pullsock)
		ev_break(loop, EVBREAK_ALL);
}

void child_end_cb(struct ev_loop * loop, ev_child * c, int event) {
	struct child_job * j = get_child(c->rpid);
	if(!j)
		return;

	ev_timer_stop(loop, &j->timer);
	// If the I/O watcher is still active, call the callback one more
	// time to make sure the buffer is flushed.
	if(ev_is_active(&j->io))
		child_io_cb(loop, &j->io, EV_READ);

	close(j->io.fd);
	ev_io_stop(loop, &j->io);

	// If there's nothing in the I/O buffer, write an empty string so
	// there's something to pack into the JSON response.
	if(j->bufused == 0)
		strcpy(j->buffer, "");

	if(j->service >= 0) {
		obj_for_ending(j, j->buffer, WEXITSTATUS(c->rstatus), 0, 1);
		logit(DEBUG, "Child %d ended with %d. Sending \"%s\" upstream",
			c->rpid, c->rstatus, j->buffer);
	} else 
		logit(DEBUG, "Non-check child %d ended with %d. It said \"%s\"",
			c->rpid, c->rstatus, j->buffer);
	json_decref(j->input);
	free(j);
	if(--runningjobs == 0 && !pullsock)
		ev_break(loop, EVBREAK_ALL);
}

void recv_job_cb(struct ev_loop * loop, ev_io * i, int event) {
	while(1) {
		zmq_msg_t inmsg;
#if ZMQ_VERSION_MAJOR == 2
		int64_t rcvmore = 0;
#elif ZMQ_VERSION_MAJOR >= 3
		int rcvmore = 0;
#endif
		size_t rms = sizeof(rcvmore);

		zmq_msg_init(&inmsg);
		if(zmq_msg_recv(&inmsg, i->data, ZMQ_DONTWAIT) == -1) {
			// There are no more messages to process - break the loop
			if(errno == EAGAIN)
				break;
			// There MAY be more messages to process - continue the loop
			else if(errno == EINTR)
				continue;

			// There was an unhandled error - break the loop
			// If this is recoverable, use heartbeats to recover the socket.
			// Above all though, break the loop there isn't a chance of
			// a busy loop.
			logit(ERR, "Error receiving message from broker %s",
				zmq_strerror(errno));
			break;
		}

		zmq_getsockopt(i->data, ZMQ_RCVMORE, &rcvmore, &rms);
		// We only want the last frame in the multi-part message
		// A NagMQ invariant is that the last frame of multi-part messages
		// will always be JSON.
		if(rcvmore) {
			zmq_msg_close(&inmsg);
			continue;
		}

		do_kickoff(loop, &inmsg);
	}
}

#if ZMQ_VERSION_MAJOR >= 3
void sock_monitor_cb(struct ev_loop * loop, ev_io * i, int event) {
	while(1) {
		void * sock = i->data;
		uint16_t event;
		int32_t value;
		zmq_msg_t addrmsg, eventmsg;
		int rc, shouldlog = 1;

		zmq_msg_init(&eventmsg);
		rc = zmq_msg_recv(&eventmsg, sock, ZMQ_DONTWAIT);
		if(rc == -1) {
			if(errno == EAGAIN || errno == ETERM)
				break;
			else if(errno == EINTR)
				continue;
			else {
				logit(ERR, "Error receiving socket monitor message %s",
					zmq_strerror(errno));
				break;
			}
		}

		if(!zmq_msg_more(&eventmsg)) {
			logit(ERR, "Message should have been multipart, is only one part");
			break;
		}

		const char* eventdata = (char*)zmq_msg_data(&eventmsg);
		memcpy(&event, eventdata, sizeof(event));
		memcpy(&value, eventdata + sizeof(event), sizeof(value));
		zmq_msg_close(&eventmsg);

		zmq_msg_init(&addrmsg);
		rc = zmq_msg_recv(&addrmsg, sock, ZMQ_DONTWAIT);
		if(rc == -1) {
			if(errno == EAGAIN || errno == ETERM)
				break;
			else if(errno == EINTR)
				continue;
			else {
				logit(ERR, "Error receiving socket monitor message %s",
					zmq_strerror(errno));
				break;
			}
		}

		if(event == 0) {
			zmq_close(sock);
			ev_io_stop(loop, i);
			return;
		}

		// These are super chatty log messages, skip em.
		switch(event) {
			case ZMQ_EVENT_CLOSED:
			case ZMQ_EVENT_CONNECT_DELAYED:
			case ZMQ_EVENT_CONNECT_RETRIED:
				shouldlog = 0;
				break;
		}

		if(!shouldlog) {
			zmq_msg_close(&addrmsg);
			continue;
		}

		char * event_string;
		switch(event) {
			case ZMQ_EVENT_CONNECTED:
				event_string = "Socket event on %.*s: connection established (fd: %d)";
				if(i == &pullmonio)
					pull_connected = 1;
				else if(i == &pushmonio)
					push_connected = 1;
				break;
			// This is super chatty. Commenting it out to reduce log chattyness
			// case ZMQ_EVENT_CONNECT_DELAYED:
			// 	event_string = "Socket event on %.*s: synchronous connect failed, it's being polled";
			// 	break;
			// case ZMQ_EVENT_CONNECT_RETRIED:
			// 	event_string = "Socket event on %.*s: asynchronous connect / reconnection attempt (ivl: %d)";
			// 	break;
			case ZMQ_EVENT_LISTENING:
				event_string = "Socket event on %.*s: socket bound to an address, ready to accept (fd: %d)";
				break;
			case ZMQ_EVENT_BIND_FAILED:
				event_string = "Socket event on %.*s: socket could not bind to an address (errno: %d)";
				break;
			case ZMQ_EVENT_ACCEPTED:
				event_string = "Socket event on %.*s: connection accepted to bound interface (fd: %d)";
				break;
			case ZMQ_EVENT_ACCEPT_FAILED:
				event_string = "Socket event on %.*s: could not accept client connection (errno: %d)";
				break;
			// This is super chatty. Commenting it out to reduce log chattyness
			// case ZMQ_EVENT_CLOSED:
			// 	event_string = "Socket event on %.*s: connection closed (fd: %d)";
			// 	break;
			case ZMQ_EVENT_CLOSE_FAILED:
				event_string = "Socket event on %.*s: connection couldn't be closed (errno: %d)";
				break;
			case ZMQ_EVENT_DISCONNECTED:
				event_string = "Socket event on %.*s: broken session (fd: %d)";
				if(i == &pullmonio)
					pull_connected = 0;
				else if(i == &pushmonio)
					push_connected = 0;
				break;
			default:
				event_string = "Unknown socket event on %.*s: %d";
				break;
		}

		logit(INFO, event_string, zmq_msg_size(&addrmsg),
			(char*)zmq_msg_data(&addrmsg), value);
		zmq_msg_close(&addrmsg);
	}
}

void setup_sockmonitor(struct ev_loop * loop, ev_io * ioev, void * sock) {
	char channel[64];
	snprintf(channel, 64, "inproc://monitor_%p", sock);

	if(ev_is_active(ioev)) {
		ev_io_stop(loop, ioev);
		void * monsock = ioev->data;
		zmq_close(monsock);
	}

	zmq_socket_monitor(sock, channel, ZMQ_EVENT_ALL);
	int fd = 0;
	size_t fdsize = sizeof(fd);

	void * monsock = zmq_socket(zmqctx, ZMQ_PAIR);
	zmq_connect(monsock, channel);
	zmq_getsockopt(monsock, ZMQ_FD, &fd, &fdsize);
	ev_io_init(ioev, sock_monitor_cb, fd, EV_READ);
	ioev->data = monsock;
	ev_io_start(loop, ioev);

	logit(DEBUG, "Registered %s for socket monitoring on %d", channel, fd);

	// Because the events are edge triggered, we have to empty the queue
	// before starting the libev loop.
	sock_monitor_cb(loop, ioev, EV_READ);
}
#endif

void handle_end(struct ev_loop * loop, ev_signal * w, int revents) {
	zmq_close(pullsock);
	pullsock = NULL;
	ev_io_stop(loop, &pullio);
	ev_signal_stop(loop, w);
	if(runningjobs == 0)
		ev_break(loop, EVBREAK_ALL);
	else
		logit(INFO, "Exit signal received. Waiting for %u jobs to finish", runningjobs);
}

int main(int argc, char ** argv) {
	ev_signal termhandler, huphandler;
	ev_child child_handler;
	struct ev_loop * loop;
	json_t * jobs = NULL, * results, *publisher = NULL;
	int pullfd = -1, i, daemonize = 0, iothreads = 1;
	size_t pullfds = sizeof(pullfd);
	json_t * config, *filter = NULL;
	json_error_t config_err;
	char ch, *configobj = "executor", *tmprootpath = NULL,
		*tmpunprivpath = NULL, *tmpunprivuser = NULL;
	json_error_t jsonerr;
	int32_t config_heartbeat_interval;

	while((ch = getopt(argc, argv, "vsdhc:")) != -1) {
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
			case 'c':
				configobj = optarg;
				break;
			case 'h':
				printf("%s [-dsvh] [-c name] {pathtoconfig}\n"
					"\t-d\tDaemonize\n"
					"\t-s\tUse syslog for logging\n"
					"\t-v\tVerbose logging\n"
					"\t-h\tPrint this message\n"
					"\t-c name\tOverride default config object name\n", argv[0]);
				break;
		}
	}
	if(daemonize)
		usesyslog = 1;
	
	argc -= optind;
	argv += optind;
	if(argc < 1) {
		logit(ERR, "Must supply path to executor config!");
		exit(1);
	}

	config = json_load_file(argv[0], JSON_DISABLE_EOF_CHECK, &config_err);
	if(config == NULL) {
		logit(ERR, "Error parsing config: %s: (line: %d column: %d)",
			config_err.text, config_err.line, config_err.column);
		exit(1);
	}

	if(daemonize && daemon(0, 0) < 0) {
		logit(ERR, "Error daemonizing: %s", strerror(errno));
		exit(1);
	}

#if ZMQ_VERSION_MAJOR < 4
	if(json_unpack_ex(config, &jsonerr, 0,
		"{s:{s?:o s:o s?i s?b s?b s?:o s?o s?s s?s s?s s?i s?i s?i}}",
		configobj, "jobs", &jobs, "results", &results,
		"iothreads", &iothreads, "verbose", &verbose,
		"syslog", &usesyslog, "filter", &filter,
		"publisher", &publisher, "rootpath", &tmprootpath,
		"unprivpath", &tmpunprivpath, "unprivuser", &tmpunprivuser,
		"reconnect_ivl", &reconnect_ivl,
		"reconnect_ivl_max", &reconnect_ivl_max,
		"heartbeat", &config_heartbeat_interval) != 0) {
		logit(ERR, "Error getting config %s", jsonerr.text);
		exit(-1);
	}
#else
	if(json_unpack_ex(config, &jsonerr, 0,
		"{s:{s?:o s:o s?i s?b s?b s?:o s?o s?s s?s s?s s?{s:s s:s s:s} s?i s?i s?i}}",
		configobj, "jobs", &jobs, "results", &results,
		"iothreads", &iothreads, "verbose", &verbose,
		"syslog", &usesyslog, "filter", &filter,
		"publisher", &publisher, "rootpath", &tmprootpath,
		"unprivpath", &tmpunprivpath, "unprivuser", &tmpunprivuser,
		"curve", "publickey", &curve_public, "privatekey", &curve_private,
		"serverkey", &curve_server, "reconnect_ivl", &reconnect_ivl,
		"reconnect_ivl_max", &reconnect_ivl_max,
		"heartbeat", &config_heartbeat_interval) != 0) {
		logit(ERR, "Error getting config: %s", jsonerr.text);
		exit(-1);
	}
#endif

	parse_filter(filter,0);

	gethostname(myfqdn, sizeof(myfqdn));
	gethostname(mynodename, sizeof(mynodename));
	for(i = 0; i < sizeof(mynodename); i++) {
		if(mynodename[i] == '.') {
			mynodename[i] = '\0';
			break;
		}
	}

	init_heartbeat(config_heartbeat_interval);

	if(tmprootpath) {
		rootpath = strdup(tmprootpath);
		rootpathlen = strlen(rootpath);
	}

	if(tmpunprivpath) {
		unprivpath = strdup(tmpunprivpath);
		unprivpathlen = strlen(unprivpath);
	}

	if(tmpunprivuser) {
		struct passwd * pwdent = getpwnam(tmpunprivuser);
		if(pwdent == NULL) {
			logit(ERR, "Error looking up user %s: %d", tmpunprivuser, errno);
			exit(-1);
		}
		runas = pwdent->pw_uid;
	}

#if ZMQ_VERSION_MAJOR > 3
	if(curve_public)
		curve_public = strdup(curve_public);
	if(curve_private)
		curve_private = strdup(curve_private);
	if(curve_server)
		curve_server = strdup(curve_server);
#endif

	zmqctx = zmq_init(iothreads);
	if(zmqctx == NULL)
		exit(-1);

	loop = ev_default_loop(0);

	pushsock = zmq_socket(zmqctx, ZMQ_PUSH);
	if(pushsock == NULL) {
		logit(ERR, "Error creating results socket %d", errno);
		exit(-1);
	}
	parse_sock_directive(pushsock, results, 0);
	pushsockdef = results;
	logit(DEBUG, "Setup worker push socket");

	if(jobs) {
		pullsock = zmq_socket(zmqctx, ZMQ_PULL);
		if(pullsock == NULL) {
			logit(ERR, "Error creating jobs socket %d", errno);
			exit(-1);
		}
		parse_sock_directive(pullsock, jobs, 0);
		pullsockdef = jobs;
		logit(DEBUG, "Setup worker pull sock");
	} else if(publisher) {
		pullsock = zmq_socket(zmqctx, ZMQ_SUB);
		if(pullsock == NULL) {
			logit(ERR, "Error creating publisher socket %d", errno);
			exit(-1);
		}
		parse_sock_directive(pullsock, publisher, 0);
		pullsockdef = publisher;
		pullsock_type = ZMQ_SUB;
		logit(DEBUG, "Setup worker pull sock");
	} else {
		logit(ERR, "Must supply either a jobs or publisher socket for worker");
		exit(-1);
	}

	zmq_getsockopt(pullsock, ZMQ_FD, &pullfd, &pullfds);
	if(pullfd == -1) {
		logit(ERR, "Error getting fd for pullsock");
		exit(-1);
	}
	ev_io_init(&pullio, recv_job_cb, pullfd, EV_READ);
	pullio.data = pullsock;
	ev_io_start(loop, &pullio);

	ev_signal_init(&termhandler, handle_end, SIGTERM);
	ev_signal_start(loop, &termhandler);
	ev_signal_init(&huphandler, handle_end, SIGHUP);
	ev_signal_start(loop, &huphandler);
	ev_child_init(&child_handler, child_end_cb, 0, 0);
	ev_child_start(loop, &child_handler);

#if ZMQ_VERSION_MAJOR >= 3
	setup_sockmonitor(loop, &pullmonio, pullsock);
	setup_sockmonitor(loop, &pushmonio, pushsock);
#endif

	if(config_heartbeat_interval > 0)
		send_heartbeat(loop);

	logit(INFO, "Starting mqexec event loop");
	ev_run(loop, 0);
	logit(INFO, "mexec event loop terminated");

	if(pullsock)
		zmq_close(pullsock);
	zmq_close(pushsock);
	zmq_term(zmqctx);

	json_decref(config);
	return 0;
}
