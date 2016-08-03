#include "json.h"
#include <zmq.h>
#include "nebstructs.h"

struct socket_list {
    void* sock;
    int fd;
    int mon_fd;
    void* mon_sock;
    const char* name;
    void (*processing_fn)(zmq_msg_t* msg);
    struct socket_list* next;
};

void process_pull_msg(zmq_msg_t* payload_msg);
void free_cb(void* ptr, void* hint);
void* getsock(char* what, int type, json_t* def);
void process_payload(struct payload* payload);
void* zap_handler(void* zapsock);
void setup_sockmonitor(struct socket_list* sock);
int handle_pubstartup(void* sock);
void register_zmq_sock_for_pull(void* sock);

struct payload* parse_service_check(nebstruct_service_check_data* state, int keep_auxdata);
struct payload* parse_host_check(nebstruct_host_check_data* state, int keep_auxdata);
struct payload* parse_event_handler(nebstruct_event_handler_data* state, int keep_auxdata);
struct payload* parse_notification(nebstruct_notification_data* state, int keep_auxdata);

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
