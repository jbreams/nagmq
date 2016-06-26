#include "json.h"
#include <zmq.h>

void process_pull_msg(zmq_msg_t* payload_msg);
int handle_timedevent(int which, void* obj);
void free_cb(void* ptr, void* hint);
void* getsock(char* what, int type, json_t* def);
void process_payload(struct payload* payload);
void* zap_handler(void* zapsock);
void setup_sockmonitor(void* sock);
int handle_pubstartup(json_t* def);

#ifndef ZMQ_DONTWAIT
#define ZMQ_DONTWAIT ZMQ_NOBLOCK
#endif
#if ZMQ_VERSION_MAJOR == 2
#define zmq_msg_send(msg, sock, opt) zmq_send(sock, msg, opt)
#define zmq_msg_recv(msg, sock, opt) zmq_recv(sock, msg, opt)
#define ZMQ_POLL_MSEC 1000  //  zmq_poll is usec
#elif ZMQ_VERSION_MAJOR >= 3
#define ZMQ_POLL_MSEC 1  //  zmq_poll is msec
#endif
