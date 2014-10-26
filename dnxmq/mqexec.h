#include "config.h"
#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif
#include <zmq.h>
#include <jansson.h>
#include "zmq3compat.h"

#ifndef MAX_PLUGIN_OUTPUT_LENGTH
#define MAX_PLUGIN_OUTPUT_LENGTH 8192
#endif

// The child job structure (where all the good stuff happens)
struct child_job {
	json_t * input;
	char buffer[MAX_PLUGIN_OUTPUT_LENGTH];
	size_t bufused;
	struct timeval start;
	double latency;
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

// Logging functions
#define ERR 2
#define DEBUG 1
#define INFO 0
void logit(int level, char * fmt, ...);

// Filter functions
int parse_filter(json_t * in, int or);
int match_filter(json_t * input);

// Kickoff functions
void do_kickoff(struct ev_loop * loop, zmq_msg_t * inmsg);

// Child management functions
void add_child(struct child_job * job);
struct child_job * get_child(pid_t pid);

// Heartbeat functions
void send_heartbeat(struct ev_loop * loop);
void init_heartbeat(int32_t configed_interval);
void process_heartbeat(json_t * inputmsg);
void subscribe_heartbeat(void * sock);

// Socket setup functions
void parse_sock_directive(void * socket, json_t * arg, int bind);
void setup_sockmonitor(struct ev_loop * loop, ev_io * ioev, void * sock);

// I/O Callbacks
void child_io_cb(struct ev_loop * loop, ev_io * i, int event);
void child_timeout_cb(struct ev_loop * loop, ev_timer * t, int event);
void child_end_cb(struct ev_loop * loop, ev_child * c, int event);
void recv_job_cb(struct ev_loop * loop, ev_io * i, int event);
void free_cb(void * data, void * hint);
