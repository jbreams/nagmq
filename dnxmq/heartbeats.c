#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <time.h>
#include "mqexec.h"

int32_t last_sent_seq = -1, last_recv_seq = -1;
int32_t heartbeat_interval = -1, heartbeat_curr_interval = -1;
time_t last_heartbeat = 0;
char heartbeat_reply_string[255];
ev_timer heartbeat_timer;
extern int pull_connected, push_connected;

extern char myfqdn[255];

extern void * pushsock, *pullsock, *zmqctx;
extern ev_io pullio, pullmonio, pushmonio;
extern json_t * pushsockdef, *pullsockdef;
extern int pullsock_type;

void init_heartbeat(int32_t configed_interval) {
	if(configed_interval < 1)
		return;

	struct timeval randseed;
	gettimeofday(&randseed, NULL);
	randseed.tv_sec ^= randseed.tv_usec;
	srand((unsigned int)randseed.tv_sec);
	snprintf(heartbeat_reply_string, sizeof(heartbeat_reply_string),
		"%s-%08x", myfqdn, rand());
	logit(DEBUG, "Setting heartbeat reply-to name to \"%s\"", heartbeat_reply_string);
	last_sent_seq = rand();
	heartbeat_interval = configed_interval;
	heartbeat_curr_interval = 1;
}

void subscribe_heartbeat(void * sock) {
	if(heartbeat_interval > 0) {
		char * heartbeat_subscribe = malloc(
			sizeof(heartbeat_reply_string) + sizeof("pong  "));
		size_t hbslen = sprintf(heartbeat_subscribe, "pong %s", heartbeat_reply_string);

		logit(DEBUG, "Subscribing to %s", heartbeat_subscribe);
		zmq_setsockopt(sock, ZMQ_SUBSCRIBE, heartbeat_subscribe, hbslen);
		free(heartbeat_subscribe);
	}
	else {
		logit(DEBUG, "Not Subscribing %d", heartbeat_interval);
	}
}

void process_heartbeat(json_t * inputmsg) {
	char * replyto;
	int32_t sequence;
	if(json_unpack(inputmsg, "{ s:s s:i }",
		"pong_target", &replyto,
		"sequence", &sequence) != 0) {
		logit(ERR, "Error unpacking pong message");
		return;
	}
	if(strncmp(replyto, heartbeat_reply_string, sizeof(heartbeat_reply_string)) != 0) {
		logit(DEBUG, "Received someone else's pong message? %s != %s",
			replyto, heartbeat_reply_string);
		return;
	}

	last_recv_seq = sequence;
	logit(DEBUG, "Received pong message (sequence: %08x)", last_recv_seq);
}

void heartbeat_timeout_cb(struct ev_loop * loop, ev_timer * t, int event) {
	ev_tstamp after = (ev_now(loop) - last_heartbeat);
	int pullfd;
	size_t pullfds = sizeof(pullfd);

	if(after < heartbeat_curr_interval) {
		ev_timer_set(t, heartbeat_curr_interval - after, 0);
		ev_timer_start(loop, t);
		return;
	} else
		ev_timer_stop(loop, t);

	if(last_recv_seq < 0) {
		if(pull_connected)
			heartbeat_curr_interval = 1;
		logit(DEBUG, "We haven't received anything yet");
		send_heartbeat(loop);
		return;
	}
	heartbeat_curr_interval = heartbeat_interval;

	if(last_recv_seq == last_sent_seq) {
		logit(DEBUG, "Heartbeat didn't time out! Resetting timer.");
		send_heartbeat(loop);
		return;
	}

	if(last_recv_seq != -1) {
		logit(DEBUG, "We recieved a pong message, but it wasn't right. Retrying. (%08x != %08x)",
			last_recv_seq, last_sent_seq, last_recv_seq);
		send_heartbeat(loop);
		return;
	}

	logit(INFO, "Heartbeat timed out. Resetting sockets. (%08x != %08x)",
		last_recv_seq, last_sent_seq);
	zmq_close(pushsock);
	pushsock = zmq_socket(zmqctx, ZMQ_PUSH);
	if(pushsock == NULL) {
		logit(ERR, "Unable to create new results socket. Cannot continue: %s",
			zmq_strerror(errno));
		exit(1);
	}
	parse_sock_directive(pushsock, pushsockdef, 0);

	ev_io_stop(loop, &pullio);
	recv_job_cb(loop, &pullio, EV_READ);
	zmq_close(pullsock);
	pullsock = zmq_socket(zmqctx, pullsock_type);
	if(pullsock == NULL) {
		logit(ERR, "Unable to create new jobs socket. Cannot continue: %s",
			zmq_strerror(errno));
		exit(1);
	}
	parse_sock_directive(pullsock, pullsockdef, 0);
	zmq_getsockopt(pullsock, ZMQ_FD, &pullfd, &pullfds);
	if(pullfd == -1) {
		logit(ERR, "Error getting fd for pullsock");
		exit(-1);
	}
	ev_io_init(&pullio, recv_job_cb, pullfd, EV_READ);
	pullio.data = pullsock;
	ev_io_start(loop, &pullio);

#if ZMQ_VERSION_MAJOR >= 3
	setup_sockmonitor(loop, &pullmonio, pullsock);
	setup_sockmonitor(loop, &pushmonio, pushsock);
#endif
	last_recv_seq = -1;

	send_heartbeat(loop);
}

void send_heartbeat(struct ev_loop * loop) {
	json_t * output;
	zmq_msg_t outputmsg;
	int rc;

	if(!push_connected) {
		logit(DEBUG, "Results socket isn't connected. Not sending heartbeat.");
		last_heartbeat = ev_now(loop);

		if(ev_is_active(&heartbeat_timer))
			ev_timer_stop(loop, &heartbeat_timer);
		ev_timer_init(&heartbeat_timer, heartbeat_timeout_cb, heartbeat_curr_interval, 0);
		ev_timer_start(loop, &heartbeat_timer);
		return;
	}

	output = json_pack("{s:s s:i s:s}",
		"type", "ping",
		"sequence", ++last_sent_seq,
		"replyto", heartbeat_reply_string
	);
	if(output == NULL) {
		logit(ERR, "Error allocating heartbeat message payload");
		return;
	}
	char * strout= json_dumps(output, JSON_COMPACT);
	json_decref(output);
	zmq_msg_init_data(&outputmsg, strout, strlen(strout), free_cb, NULL);

	last_heartbeat = ev_now(loop);

	if(ev_is_active(&heartbeat_timer))
		ev_timer_stop(loop, &heartbeat_timer);
	ev_timer_init(&heartbeat_timer, heartbeat_timeout_cb, heartbeat_curr_interval, 0);
	ev_timer_start(loop, &heartbeat_timer);

	if(zmq_msg_send(&outputmsg, pushsock, ZMQ_DONTWAIT) == -1)
		logit(ERR, "Error sending heartbeat message: %s", zmq_strerror(errno));
	else {
		logit(DEBUG, "Sent heartbeat message. Next timeout in %d seconds. (Sequence: %08x)",
			heartbeat_curr_interval, last_sent_seq);
	}
	zmq_msg_close(&outputmsg);
}
