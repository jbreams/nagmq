#include "config.h"
#include <zmq.h>
#ifdef HAVE_ICINGA
#include "icinga.h"
#else
#include "nagios.h"
#endif
#include <string.h>

extern void * zmq_ctx, *pullsock, *reqsock, *pubext;
void * pullmon = NULL, *reqmon = NULL, *pubmon = NULL;
int pullmonfd = -1, reqmonfd = -1, pubmonfd;

#if ZMQ_VERSION_MAJOR >= 3 && defined(HAVE_NAGIOS4)
int sock_monitor_cb(int sd, int events, void * sock) {
	while(1) {
		zmq_msg_t addrmsg, eventmsg;
		int rc, shouldlog = 1;
		uint16_t event;
		int32_t value;

		zmq_msg_init(&eventmsg);
		rc = zmq_msg_recv(&eventmsg, sock, ZMQ_DONTWAIT);
		if(rc == -1) {
			if(errno == EAGAIN || errno == ETERM)
				break;
			else if(errno == EINTR)
				continue;
			else {
				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error receiving socket monitor message %s",
					zmq_strerror(errno));
				break;
			}
		}

		if(!zmq_msg_more(&eventmsg)) {
			logit(NSLOG_RUNTIME_ERROR, TRUE, "Message should have been multipart, is only one part");
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
				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error receiving socket monitor message %s",
					zmq_strerror(errno));
				break;
			}
		}

		// These are super chatting log messages, skip em.
		switch(event) {
			case ZMQ_EVENT_CLOSED:
			case ZMQ_EVENT_CONNECT_DELAYED:
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
				event_string = "NagMQ socket event on %.*s: connection established (fd: %d)";
				break;
			// This is super chatty. Commenting it out to reduce log chattyness
			// case ZMQ_EVENT_CONNECT_DELAYED:
			// 	event_string = "NagMQ socket event on %.*s: synchronous connect failed, it's being polled";
			// 	break;
			case ZMQ_EVENT_CONNECT_RETRIED:
				event_string = "NagMQ socket event on %.*s: asynchronous connect / reconnection attempt (ivl: %d)";
				break;
			case ZMQ_EVENT_LISTENING:
				event_string = "NagMQ socket event on %.*s: socket bound to an address, ready to accept (fd: %d)";
				break;
			case ZMQ_EVENT_BIND_FAILED:
				event_string = "NagMQ socket event on %.*s: socket could not bind to an address (errno: %d)";
				break;
			case ZMQ_EVENT_ACCEPTED:
				event_string = "NagMQ socket event on %.*s: connection accepted to bound interface (fd: %d)";
				break;
			case ZMQ_EVENT_ACCEPT_FAILED:
				event_string = "NagMQ socket event on %.*s: could not accept client connection (errno: %d)";
				break;
			// This is super chatty. Commenting it out to reduce log chattyness
			// case ZMQ_EVENT_CLOSED:
			// 	event_string = "NagMQ socket event on %.*s: connection closed (fd: %d)";
			// 	break;
			case ZMQ_EVENT_CLOSE_FAILED:
				event_string = "NagMQ socket event on %.*s: connection couldn't be closed (errno: %d)";
				break;
			case ZMQ_EVENT_DISCONNECTED:
				event_string = "NagMQ socket event on %.*s: broken session (fd: %d)";
				break;
			default:
				event_string = "Unknown NagMQ socket event on %.*s: %d";
				break;
		}

		logit(NSLOG_INFO_MESSAGE, TRUE, event_string, zmq_msg_size(&addrmsg),
			(char*)zmq_msg_data(&addrmsg), value);
		zmq_msg_close(&addrmsg);
	}
	return 0;
}

extern iobroker_set *nagios_iobs;

void setup_sockmonitor(void * sock) {
	char channel[64];
	snprintf(channel, 64, "inproc://monitor_%p", sock);

	zmq_socket_monitor(sock, channel, ZMQ_EVENT_ALL);
	int fd = 0;
	size_t fdsize = sizeof(fd);

	void * monsock = zmq_socket(zmq_ctx, ZMQ_PAIR);
	zmq_connect(monsock, channel);
	zmq_getsockopt(monsock, ZMQ_FD, &fd, &fdsize);

	if(sock == pullsock) {
		pullmon = monsock;
		pullmonfd = fd;
	}
	else if(sock == reqsock) {
		reqmon = monsock;
		reqmonfd = fd;
	}
	else if(sock == pubext) {
		pubmon = monsock;
		pubmonfd = fd;
	}

	iobroker_register(nagios_iobs, fd, monsock, sock_monitor_cb);

	log_debug_info(DEBUGL_PROCESS, DEBUGV_BASIC,
		"Registered %s for socket monitoring on %d\n", channel, fd);

	// Because the events are edge triggered, we have to empty the queue
	// before starting the libev loop.
	sock_monitor_cb(0, 0, monsock);
}
#else

// This is a Nagios 4-only feature.
void setup_sockmonitor(void * sock) {}
#endif
