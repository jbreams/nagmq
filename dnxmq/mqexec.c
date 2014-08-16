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
#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif
#include <zmq.h>
#include <jansson.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>
#ifdef HAVE_PCRE
#include <pcre.h>
#else
#include <regex.h>
#endif
#include "zmq3compat.h"
#include <wordexp.h>
#include <time.h>

#ifndef MAX_PLUGIN_OUTPUT_LENGTH
#define MAX_PLUGIN_OUTPUT_LENGTH 8192
#endif

void * zmqctx;
// Worker Sockets
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

struct child_job {
	json_t * input;
	char buffer[MAX_PLUGIN_OUTPUT_LENGTH];
	size_t bufused;
	struct timeval start;
	int service;
	int timeout;
	pid_t pid;
	ev_io io;
	ev_timer timer;
	struct child_job * next;
	char * host_name;
	char * service_description;
	char * type;
};

struct child_job * runningtable[2048];

void add_child(struct child_job * job) {
	uint32_t hash = job->pid * 0x9e370001UL;
	hash >>= 21;
	job->next = runningtable[hash];
	runningtable[hash] = job;
}

struct child_job * get_child(pid_t pid) {
	uint32_t hash = pid * 0x9e370001UL;
	hash >>= 21; //(32 bits - 11)
	struct child_job * ret = runningtable[hash], *last = NULL;
	while(ret && ret->pid != pid) {
		last = ret;
		ret = ret->next;
	}
	if(!ret)
		return NULL;
	if(last == NULL)
		runningtable[hash] = ret->next;
	else
		last->next = ret->next;
	return ret; 
}

struct filter {
#ifdef HAVE_PCRE
	pcre * regex;
	pcre_extra * extra;
#else
	regex_t regex;
#endif
	char field[64];
	char or;
	int fqdn;
	int nodename;
	int isnot;
	struct filter * next;
} *filterhead = NULL, *filtertail = NULL;

#define ERR 2
#define DEBUG 1
#define INFO 0
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

int parse_filter(json_t * in, int or) {
	if(json_is_object(in)) {
		char * field = NULL;
		char * match = NULL;
		int icase = 0, dotall = 0;
		json_t * orobj = NULL;

		struct filter * newfilt = calloc(1, sizeof(struct filter));
		if(json_unpack(in, "{ s?:s s:s s?:o s?:b s?:b s?:b s?:b s?b }",
			"match", &match, "field", &field, "or", &orobj,
			"caseless", &icase, "dotall", &dotall, "not", &newfilt->isnot,
			"fqdn", &newfilt->fqdn, "nodename", &newfilt->nodename) < 0) {
			logit(ERR, "Error parsing filter definition.");
			free(newfilt);
			return -1;
		}

		strncpy(newfilt->field, field, sizeof(newfilt->field) - 1);
		if(match) {
#ifdef HAVE_PCRE
			const char * errptr = NULL;
			int errofft = 0, options = PCRE_NO_AUTO_CAPTURE;
			if(icase)
				options |= PCRE_CASELESS;
			if(dotall)
				options |= PCRE_DOTALL;
			newfilt->regex = pcre_compile(match, options, &errptr,
				&errofft, NULL);
			if(newfilt->regex == NULL) {
				logit(ERR, "Error compiling regex for %s at position %d: %s",
					field, errptr, errofft);
				free(newfilt);
				return -1;
			}
			
			newfilt->extra = pcre_study(newfilt->regex, 0, &errptr);
			if(errptr != NULL) {
				logit(ERR, "Error studying regex: %s", errptr);
				free(newfilt);
				return -1;
			}
#else
			int options = REG_EXTENDED | REG_NOSUB;
			if(icase)
				options |= REG_ICASE;
			int rc = regcomp(&newfilt->regex, match, options);
			if(rc != 0) {
				logit(ERR, "Error compiling regex for %s: %s",
					field, strerror(rc));
				free(newfilt);
				return -1;
			}
#endif
		}
		if(!filterhead) {
			filterhead = newfilt;
			filtertail = newfilt;
		} else
			filtertail->next = newfilt;

		if(json_is_true(orobj))
			newfilt->or = 1;	
		else if(orobj)
			parse_filter(orobj, 1);
	} else if(json_is_array(in)) {
		int x;
		for(x = 0; x < json_array_size(in); x++) {
			json_t * t = json_array_get(in, x);
			if(parse_filter(t, or) < 0)
				return -1;
		}
	}
	return 0;
}

int match_filter(json_t * input) {
	struct filter *cur;
	for(cur = filterhead; cur != NULL; cur = cur->next) {
		int res = 1;
		const char * tomatch;
		json_t * field;
		if((field = json_object_get(input, cur->field)) == NULL)
			continue;
		if(!json_is_string(field))
			continue;
		tomatch = json_string_value(field);
		if(cur->fqdn)
			res = strcasecmp(tomatch, myfqdn);
		else if(cur->nodename)
			res = strcasecmp(tomatch, mynodename);
		else {
#ifdef HAVE_PCRE
			int ovec[33];
			res = pcre_exec(cur->regex, cur->extra,
				tomatch, strlen(tomatch), 0, 0, ovec, 33);
			res = res < 0 ? 1 : 0;
#else
			regmatch_t ovec[33];
			res = regexec(&cur->regex, tomatch, 33, ovec, 0);
#endif
		}
		if(cur->isnot == 1) {
			res = res == 0 ? 1 : 0;
			logit(DEBUG, "Inverting filter because of not clause");
		}
		if(cur->or == 1 && res == 0)
			return 1;
		else if(cur->or == 0 && res != 0)
			return 0;
		else
			break;
	}
	return 1;
}

void free_cb(void * data, void * hint) {
	free(data);
}

void obj_for_ending(struct child_job * j, const char * output,
	int return_code, int early_timeout, int exited_ok) {
	zmq_msg_t outmsg;
	const char * keys[] = { "host_name", "service_description",
		"check_options", "scheduled_check", "reschedule_check",
		"latency", "early_timeout", "check_type", NULL };
	struct timeval finish;
	int i, rc;

	if(j->start.tv_sec == 0)
		gettimeofday(&j->start, NULL);
	gettimeofday(&finish, NULL);
	json_t * jout = json_pack(
		"{ s:s s:i s:i s:i s:{ s:i s:i } s:{ s:i s:i } s:s }",
		"output", output, "return_code", return_code,
		"exited_ok", exited_ok, "early_timeout", early_timeout,
		"start_time", "tv_sec", j->start.tv_sec,
		"tv_usec", j->start.tv_usec, "finish_time", "tv_sec",
		finish.tv_sec, "tv_usec", finish.tv_usec, "type",
		j->service ? "service_check_processed":"host_check_processed");

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
	do {
		rc = zmq_msg_send(&outmsg, pushsock, 0);
		if(rc == -1 && errno != EINTR) {
			logit(ERR, "Error sending message: %s", zmq_strerror(errno));
			break;
		}
	} while(rc < 0);
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
	if(get_child(j->pid)) {
		kill(j->pid, SIGKILL);
	}

	if(j->service >= 0) {
		obj_for_ending(j, "Check timed out", 3, 1, 1);
		logit(DEBUG, "Child %d timed out. Sending timeout message upstream",
			j->pid);
	} else
		logit(DEBUG, "Non-check child %d timed out",
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
	if(ev_is_active(&j->io)) {
		child_io_cb(loop, &j->io, EV_READ);
		close(j->io.fd);
	}
	ev_io_stop(loop, &j->io);

	if(!j->bufused)
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

int check_jail(const char * cmdline) {
	if(!unprivpath && !rootpath)
		return 1;
	if(rootpath && strncmp(cmdline, rootpath, rootpathlen) == 0)
		return 1;
	else if(unprivpath && strncmp(cmdline, unprivpath, unprivpathlen) == 0)
		return 2;
	return 0;
}

void do_kickoff(struct ev_loop * loop, zmq_msg_t * inmsg) {
	json_t * input;
	struct child_job * j;
	char * type, *command_line, *hostname = NULL, *svcdesc = NULL;
	json_error_t err;
	int fds[2];
	pid_t pid;
	int timeout = 0, okay_to_run;

	input = json_loadb(zmq_msg_data(inmsg), zmq_msg_size(inmsg), 0, &err);
	zmq_msg_close(inmsg);
	if(input == NULL) {
		logit(ERR, "Error loading request from broker: %s (line %d col %d)",
			err.text, err.line, err.column);
		return;
	}

	if(json_unpack(input, "{ s:s s:s s?:i s?:s s?:s }",
		"type", &type, "command_line", &command_line,
		"timeout", &timeout, "host_name", &hostname,
		"service_description", &svcdesc) != 0) {
		logit(ERR, "Error unpacking JSON payload during kickoff");
		json_decref(input);
		return;
	}

	if(filterhead != NULL && match_filter(input) != 1) {
		logit(DEBUG, "Not running %s because of filtering", command_line);
		json_decref(input);
		return;
	}

	if(!svcdesc)
		svcdesc = "(none)";

	logit(DEBUG, "Received job from upstream: %s %s",
		type, command_line);

	j = calloc(1, sizeof(struct child_job));
	if(strcmp(type, "service_check_initiate") == 0)
		j->service = 1;
	else if(strcmp(type, "host_check_initiate") == 0)
		j->service = 0;
	else
		j->service = -1;
	j->input = input;
	j->type = type;
	j->host_name = hostname;
	j->service_description = svcdesc;

	okay_to_run = check_jail(command_line);
	if(okay_to_run == 0) {
		logit(ERR, "Refusing to execute job outside sandbox %s", command_line);
		obj_for_ending(j, "Command line outside sandbox", 3, 0, 0);
		free(j);
		json_decref(input);
		return;
	}

	if(pipe(fds) < 0 ||
		fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0) {
		logit(ERR, "Error creating pipe for %s: %s",
			command_line, strerror(errno));
		obj_for_ending(j, "Error creating pipe", 3, 0, 0);
		free(j);
		json_decref(input);
		return;		
	}

	ev_io_init(&j->io, child_io_cb, fds[0], EV_READ);
	j->io.data = j;
	ev_io_start(loop, &j->io);

	gettimeofday(&j->start, NULL);
	pid = fork();
	if(pid == 0) {
		wordexp_t expvec;
		int dn = open("/dev/null", O_RDONLY);
		if(dn < 0) {
			printf("Error redirecting stdin: %s\n", strerror(errno));
			exit(127);
		}
		dup2(fds[1], fileno(stdout));
		dup2(fds[1], fileno(stderr));
		dup2(dn, fileno(stdin));
		close(dn);
		close(fds[1]);
#ifdef TEST
		printf("Testing testing testing!\n");
		exit(0);
#else

		if(geteuid() == 0 && runas != 0 && okay_to_run == 2)
			setuid(runas);

		switch(wordexp(command_line, &expvec, WRDE_NOCMD)) {
			case 0:
				break;
			case WRDE_SYNTAX:
				printf("Error executing \"%s\". Bad syntax\n", command_line);
				exit(127);
				break;
			case WRDE_CMDSUB:
				printf("Command \"%s\" uses unsafe command substitution.\n", command_line);
				exit(127);
				break;
			case WRDE_BADVAL:
			case WRDE_BADCHAR:
				printf("Command \"%s\" uses invalid characters or variables\n", command_line);
				exit(127);
				break;
			case WRDE_NOSPACE:
				printf("Out of memory while parsing command line\n");
				exit(127);
				break;
		}

		execv(expvec.we_wordv[0], expvec.we_wordv);
		printf("Error executing shell for %s: %m", command_line);
		exit(127);
#endif
	}
	else if(pid < 0) {
		logit(ERR, "Error forking for %s: %s",
			command_line, strerror(errno));
		obj_for_ending(j, "Error forking", 3, 0, 0);
		json_decref(input);
		ev_io_stop(loop, &j->io);
		close(fds[1]);
		close(fds[0]);
		free(j);
		return;
	}
	j->pid = pid;
	add_child(j);
	close(fds[1]);

	if(timeout > 0) {
		ev_timer_init(&j->timer, child_timeout_cb, timeout, 0);
		j->timer.data = j;
		ev_timer_start(loop, &j->timer);
		j->timeout = timeout;
	}
	
	logit(DEBUG, "Kicked off %d for %s %s", pid, hostname, svcdesc);
	runningjobs++;
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
			if(errno == EAGAIN)
				break;
			if(errno == EINTR) {
				if(pullsock)
					continue;
				else
					break;
			}
			logit(ERR, "Error receiving message from broker %s",
				zmq_strerror(errno));
			continue;
		}

		zmq_getsockopt(i->data, ZMQ_RCVMORE, &rcvmore, &rms);
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
		zmq_event_t sockevent;
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
		memcpy(&(sockevent.event), eventdata, sizeof(sockevent.event));
		memcpy(&(sockevent.value), eventdata + sizeof(sockevent.event),
			sizeof(sockevent.value));
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

		// These are super chatting log messages, skip em.
		switch(sockevent.event) {
			case ZMQ_EVENT_CLOSED:
			case ZMQ_EVENT_CONNECT_DELAYED:
				shouldlog = 0;
				break;
		}

		if(!shouldlog)
			continue;

		char * event_string;
		switch(sockevent.event) {
			case ZMQ_EVENT_CONNECTED:
				event_string = "Socket event on %.*s: connection established (fd: %d)";
				break;
			// This is super chatty. Commenting it out to reduce log chattyness
			// case ZMQ_EVENT_CONNECT_DELAYED:
			// 	event_string = "Socket event on %.*s: synchronous connect failed, it's being polled";
			// 	break;
			case ZMQ_EVENT_CONNECT_RETRIED:
				event_string = "Socket event on %.*s: asynchronous connect / reconnection attempt (ivl: %d)";
				break;
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
				break;
			default:
				event_string = "Unknown socket event on %.*s: %d";
				break;
		}

		logit(INFO, event_string, zmq_msg_size(&addrmsg),
			(char*)zmq_msg_data(&addrmsg), sockevent.value);
		zmq_msg_close(&addrmsg);
	}
}

void setup_sockmonitor(struct ev_loop * loop, ev_io * ioev, void * sock) {
	char channel[64];
	snprintf(channel, 64, "inproc://monitor_%p", sock);

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
		json_t * subscribe = NULL;
		if(json_unpack(arg, "{s:s s?:b s?:o}", 
			"address", &addr, "bind", &bind, "subscribe",
			&subscribe) != 0)
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
		"{s:{s?:o s:o s?i s?b s?b s?:o s?o s?s s?s s?s s?i s?i}}",
		configobj, "jobs", &jobs, "results", &results,
		"iothreads", &iothreads, "verbose", &verbose,
		"syslog", &usesyslog, "filter", &filter,
		"publisher", &publisher, "rootpath", &tmprootpath,
		"unprivpath", &tmpunprivpath, "unprivuser", &tmpunprivuser,
		"reconnect_ivl", &reconnect_ivl,
		"reconnect_ivl_max", &reconnect_ivl_max) != 0) {
		logit(ERR, "Error getting config %s", jsonerr.text);
		exit(-1);
	}
#else
	if(json_unpack_ex(config, &jsonerr, 0,
		"{s:{s?:o s:o s?i s?b s?b s?:o s?o s?s s?s s?s s?{s:s s:s s:s} s?i s?i}}",
		configobj, "jobs", &jobs, "results", &results,
		"iothreads", &iothreads, "verbose", &verbose,
		"syslog", &usesyslog, "filter", &filter,
		"publisher", &publisher, "rootpath", &tmprootpath,
		"unprivpath", &tmpunprivpath, "unprivuser", &tmpunprivuser,
		"curve", "publickey", &curve_public, "privatekey", &curve_private,
		"serverkey", &curve_server, "reconnect_ivl", &reconnect_ivl,
		"reconnect_ivl_max", &reconnect_ivl_max) != 0) {
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
	logit(DEBUG, "Setup worker push socket");

	if(jobs) {
		pullsock = zmq_socket(zmqctx, ZMQ_PULL);
		if(pullsock == NULL) {
			logit(ERR, "Error creating jobs socket %d", errno);
			exit(-1);
		}
		parse_sock_directive(pullsock, jobs, 0);
		logit(DEBUG, "Setup worker pull sock");
	} else if(publisher) {
		pullsock = zmq_socket(zmqctx, ZMQ_SUB);
		if(pullsock == NULL) {
			logit(ERR, "Error creating publisher socket %d", errno);
			exit(-1);
		}
		parse_sock_directive(pullsock, publisher, 0);
		logit(DEBUG, "Setup worker pull sock");
	} else {
		logit(ERR, "Must supply either a jobs or publisher socket for worker");
		exit(-1);
	}

	int ivl;
	size_t ivlsize = sizeof(ivl);
	zmq_getsockopt(pullsock, ZMQ_RECONNECT_IVL, &ivl, &ivlsize);
	logit(DEBUG, "Set pull reconnect interval to %d", ivl);
	zmq_getsockopt(pushsock, ZMQ_RECONNECT_IVL, &ivl, &ivlsize);
	logit(DEBUG, "Set push reconnect interval to %d", ivl);

	zmq_getsockopt(pullsock, ZMQ_FD, &pullfd, &pullfds);
	if(pullfd == -1) {
		logit(ERR, "Error getting fd for pullsock");
		exit(-1);
	}
	ev_io_init(&pullio, recv_job_cb, pullfd, EV_READ);
	pullio.data = pullsock;
	ev_io_start(loop, &pullio);

	json_decref(config);
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

	memset(runningtable, 0, sizeof(runningtable));
	logit(INFO, "Starting mqexec event loop");
	ev_run(loop, 0);
	logit(INFO, "mexec event loop terminated");

	if(pullsock)
		zmq_close(pullsock);
	zmq_close(pushsock);
	zmq_term(zmqctx);
	return 0;
}
