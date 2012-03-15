#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>
#include <fcntl.h>
#include <pwd.h>
#include <ev.h>
#include <zmq.h>
#include <jansson.h>

#ifndef MAX_PLUGIN_OUTPUT_LENGTH
#define MAX_PLUGIN_OUTPUT_LENGTH 8192
#endif

void * zmqctx;
void * pullsock;
void * pushsock;

struct child_job {
	json_t * input;
	char buffer[MAX_PLUGIN_OUTPUT_LENGTH];
	size_t bufused;
	struct timeval start;
	int service;
	ev_io io;
	ev_child child;
};

json_t * obj_for_ending(struct child_job * j, const char * output,
	int return_code, int exited_ok) {
	const char * keys[] = { "host_name", "service_description",
		"check_options", "scheduled_check", "reschedule_check",
		"latency", "early_timeout", "check_type", NULL };
	struct timeval finish;
	int i;

	gettimeofday(&finish, NULL);
	json_t * ret = json_pack(output,
		"{ s:s s:i s:i s:{ s:i s:i } s:{ s:i s:i } s:s }",
		"output", output, "return_code", return_code,
		"exited_ok", exited_ok, "start_time", "tv_sec", j->start.tv_sec,
		"tv_usec", j->start.tv_usec, "finish_time", "tv_sec",
		finish.tv_sec, "tv_usec", finish.tv_usec, "type",
		j->service ? "service_check_processed":"host_check_processed");

	for(i = 0; keys[i] != NULL; i++) {
		json_t * val = json_object_get(j->input, keys[i]);
		if(val)
			json_object_set(ret, keys[i], val);
	}
	return ret;
}

void free_cb(void * data, void * hint) {
	free(data);
}

void child_end_cb(struct ev_loop * loop, ev_child * c, int event) {
	struct child_job * j = (struct child_job*)c->data;
	zmq_msg_t outmsg;

	child_io_cb(loop, &j->io, EV_READ);
	ev_io_stop(loop, &j->io);

	if(j->bufused)
		j->buffer[j->bufused] = '\0';
	else
		strcpy(j->buffer, "");
	json_t * jout = obj_for_ending(j, j->buffer, c->rstatus, 1);
	json_decref(j->input);
	char * output = json_dumps(jout, JSON_COMPACT);
	json_decref(jout);

	zmq_msg_init_data(&outmsg, output, strlen(output), free_cb, NULL);
	zmq_send(pushsock, &outmsg, 0);
	zmq_msg_close(&outmsg);
	free(j);
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

void pull_cb(struct ev_loop * loop, ev_io * i, int event) {
	uint32_t events = 0;
	size_t evs = sizeof(events);
	json_t * input;
	struct child_job * j;
	char * type, *command_line;
	zmq_msg_t inmsg;
	int fds[2];
	char * argv[1024];
	pid_t pid;
	int rc;

	zmq_getsockopt(pullsock, ZMQ_EVENTS, &events, &evs);
	if(events != ZMQ_POLLIN)
		return;

	zmq_msg_init(&inmsg);
	if(zmq_recv(pullsock, &inmsg, 0) != 0)
		return;

	input = json_loadb(zmq_msg_data(&inmsg),
		zmq_msg_size(&inmsg), 0, NULL);
	zmq_msg_close(&inmsg);

	if(json_unpack(input, "{ s:s s:s }",
		"type", &type, "command_line", &command_line) != 0) {
		json_decref(input);
		return;
	}

	memset(argv, 0, sizeof(argv));
	char * lck = command_line, *save = lck;
	int argc = 0;
	while(*lck) {
		if(*lck == ' ') {
			if(*(lck + 1) == ' ')
				continue;
			argv[argc++] = save;
			*(lck++) = '\0';
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

	pipe(fds);
	fcntl(fds[0], F_SETFL, O_NONBLOCK);

	j = malloc(sizeof(struct child_job));
	if(strcmp(type, "service_check_initiate") == 0)
		j->service = 1;
	else
		j->service = 0;
	j->bufused = 0;
	j->input = input;
	
	ev_io_init(&j->io, child_io_cb, fds[0], EV_READ);
	j->io.data = j;
	ev_io_start(loop, &j->io);

	
	gettimeofday(&j->start, NULL);
	pid = fork();
	if(pid == 0) {
		dup2(fds[1], fileno(stdout));
		execv(command_line, argv);
		rc = errno;
		printf("Error executing %s: %m", command_line);
		exit(errno);
	}

	ev_child_init(&j->child, child_end_cb, pid, 0);
	j->child.data = j;
	ev_child_start(loop, &j->child);
}

int main(int argc, char ** argv) {
	ev_io pullio;
	struct ev_loop  * loop;
	char *pulladdr = NULL, *pushaddr = NULL, ch;
	uid_t dropto = 0;	
	int iothreads = 1;
	int pullfd = -1;
	size_t pullfds = sizeof(pullfd);

	while((ch = getopt(argc, argv, "s:l:u:i:")) != -1) {
		switch(ch) {
			case 's':
				pushaddr = optarg;
				break;
			case 'l':
				pulladdr = optarg;
				break;
			case 'u': {
				struct passwd * u = getpwnam(optarg);
				if(!u) {
					fprintf(stderr, "User %s %m", optarg);
					exit(-1);
				}
				dropto = u->pw_uid;
			}
			break;
			case 'i':
				iothreads = atoi(optarg);
				break;
		}
	}

	if(!pushaddr || !pulladdr)
		exit(-1);

	if(dropto && getuid() == 0)
		setuid(dropto);

	zmqctx = zmq_init(iothreads);
	if(zmqctx == NULL)
		exit(-1);

	pushsock = zmq_socket(zmqctx, ZMQ_PUSH);
	if(pushsock == NULL)
		exit(-1);
	if(zmq_connect(pushsock, pushaddr) != 0)
		exit(-1);

	pullsock = zmq_socket(zmqctx, ZMQ_PULL);
	if(pullsock == NULL)
		exit(-1);
	if(zmq_connect(pullsock, pulladdr) != 0)
		exit(-1);

	zmq_getsockopt(pullsock, ZMQ_FD, &pullfd, &pullfds);
	if(pullfd == -1)
		exit(-1);

	loop = ev_default_loop(0);
	ev_io_init(&pullio, pull_cb, pullfd, EV_READ);
	ev_io_start(loop, &pullio);
	ev_run(loop, 0);

	zmq_close(pullsock);
	zmq_close(pushsock);
	zmq_term(zmqctx);
	return 0;
}
