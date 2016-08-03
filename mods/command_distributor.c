#include "string.h"
#define NSCORE 1
#include "nebcallbacks.h"
#include "nebmods.h"
#include "nebmodules.h"
#ifdef HAVE_ICINGA
#include "icinga.h"
#else
#include "nagios.h"
#endif

#include "nagmq_common.h"

static void* command_sock = NULL;
extern nebmodule* handle;

struct job {
    char* id;
    char* host_name;
    char* service_description;
    char* executor;
    int check_type;
    int check_options;
    int scheduled_check;
    int reschedule_check;
    double latency;
    time_t started;
    time_t expires;

    char* json_buf;
    size_t json_size;

    struct timed_event* timeout_event;

    UT_hash_handle hh;
};
static struct job* jobs = NULL;

static int failure_code_for_job(struct job* j) {
    if (j->service_description)
        return 2;
    return 1;
}

static void fill_check_result_from_job(struct job* job, check_result* cr) {
    init_check_result(cr);
    cr->host_name = job->host_name;
    cr->service_descr->ption = job->service_descrption;
    cr->check_type = job->check_type;
    cr->check_options = job->check_options;
    cr->scheduled_check = job->scheduled_check;
    cr->reschedule_check = job->reschedule_check;
}

static void process_failure(struct job* job, int exit_code, const char* message) {
    check_result newcr;
    fill_check_result_from_job(job, &newcr);
    newcr.return_code = exit_code;
    newcr.output = strdup(message);
    newcr.exited_ok = 1;
    newcr.early_timeout = 0;
    newcr.latency = job->latency;
}

static void free_job(struct job* j) {
    if (!j)
        return;
    struct job* found = NULL;

    HASH_FIND_STR(jobs, j->id, found);
    if (found) {
        HASH_DEL(jobs, found);
    }

    if (j->id)
        free(j->id);
    if (j->host_name)
        free(j->host_name);
    if (j->service_description)
        free(j->service_description);
    if (j->executor)
        free(j->executor);
    if (j->json_buf)
        free(j->json_buf);
    if (j->timed_event)
        remove_event(nagios_squeue, job->timeout_event);

    free(j);
}

static void free_cb(void* data, void* hint) {
    struct job* job = (struct job*)hint;
    free(job->json_buf);
    job->json_buf = NULL;
}

static struct job* job_from_event(int type, void* obj) {
    char* name;
    struct customvariablesmember* head;
    struct nebstruct_process_data* raw = obj;

    struct job* j = NULL;
    struct payload* payload = NULL;
    switch(type) {
    case NEBCALLBACK_HOST_CHECK_DATA: {
        struct nebstruct_host_check_data* state = obj;
        if (state->type != NEBTYPE_HOSTCHECK_ASYNC_PRECHECK)
            return NULL;

        j = calloc(sizeof(struct job), 1);
        host* obj = (host*)state->object_ptr;
        j->host_name = strdup(state->host_name);
        j->service_description = NULL;
        asprintf(&j->id, "host check: %s", j->host_name);
        j->check_type = state->check_type;
        j->check_options = obj->check_options;
        j->scheduled_check = 1;
        j->reschedule_check = 1;
        j->latency = state->latency;
        name = state->host_name;
        head = obj->custom_variables;

        payload = parse_host_check(obj, 0);
                                      }
        break;
    case NEBCALLBACK_SERVICE_CHECK_DATA: {
        struct nebstruct_service_check_data* state = obj;
        if (state->type != NEBTYPE_SERVICECHECK_INITIATE)
            return NULL;

        j = calloc(sizeof(struct job), 1);
        service* obj = (service*)state->object_ptr;
        check_result* cri = state->check_result_ptr;
        j->host_name = strdup(state->host_name);
        j->service_description = strdup(state->service_description);
        asprintf(&j->id, "service check: %s @ %s", j->host_name, j->service_description);
        j->check_type = state->check_type;
        j->check_options = cri->check_options;
        j->scheduled_check = cri->scheduled_check;
        j->reschedule_check = cri->reschedule_check;
        j->latency = state->latency;
        name = state->host_name;
        head = obj->custom_variables;

        payload = parse_service_check(obj, 0);
                                         }
        break;
    case NEBCALLBACK_EVENT_HANDLER_DATA: {
        struct nebstruct_event_handler_data* state = obj;
        if (state->type != NEBTYPE_EVENTHANDLER_START)
            return NULL;
        j = calloc(sizeof(struct job), 1);
        j->host_name = strdup(state->host_name);
        j->service_description = strdup(state->service_description);
        name = state->host_name;
        if (state->service_description) {
            head = ((service*)state->object_ptr)->custom_variables;
        } else {
            head = ((host*)state->object_ptr)->custom_variables;
        }

        payload = parse_event_handler(obj, 0);
                                         }
        break;
    default:
        return NULL;
    }

    payload_new_timestamp(payload, "timestamp", &raw->timestamp);
    payload_new_string(payload, "command_id", j->id);
    payload_finalize(payload);
    j->json_buf = payload->json_buf;
    j->json_size = payload->bufused;
    free(payload);

    for(; head != NULL; head = head->next) {
        if (strcmp(head->variable_name, "_MQEXEC_EXECUTOR") == 0)
            name = head->variable_value;
        else if(strcmp(head->variable_name, "_MQEXEC_IGNORE") == 0)
            name = NULL;
    }

    if (name == NULL) {
        log_debug_info(DEBUGL_CHECKS, 0, "Ignoring %s becase of config override", j->id);
        free_job(j);
        return NULL;
    }

    j->executor = strdup(name);

    return j;
}

static void process_zmq_failure(struct job* job, int myerr) {
    if (myerr == EHOSTUNREACH) {
        process_failure(job, failure_code_for_job(job), "Executor is unavailable");
    } else {
        char* errmsg;
        asprintf(&errmsg, "Error sending job: %s", zmq_strerror(myerr));
        process_failure(job, failure_code_for_job(job), errmsg);
        free(errmsg);
    }
}

static void process_timeout(struct job* job) {
    process_failure(job, failure_code_for_job(job), "Command timed out");
    j->timout_event = NULL;
    free_job(j);
}

int handle_command_data(int which, void* obj) {
    struct job* job = NULL;
    nebstruct_process_data* raw = obj;
    int rc = 0;

    job = job_from_event(which, obj);
    if (!payload || !job) {
        free_job(job);
        return ERROR;
    }

    while((rc = zmq_send(command_sock, job->executor, strlen(job->executor),
            ZMQ_SNDMORE | ZMQ_DONTWAIT)) == -1 && errno == EINTR);
    if (rc == -1) {
        process_zmq_failure(job, errno);
    }

    zmq_msg_t msg;
    zmq_msg_init_data(&msg, job->json_buf, job->json_size, free_cb, job);
    while((rc = zmq_msg_send(&msg, command_sock, ZMQ_DONTWAIT)) == -1 && errno == EINTR);
    zmq_msg_close(&msg);
    if (rc == -1) {
        process_zmq_failure(job, errno);
    }

    job->timeout_event = schedule_new_event(
        EVENT_USER_FUNCTION, TRUE, job->expires, FALSE, 0, NULL, TRUE, process_timeout, job, 0);

    HASH_ADD_STR(jobs, id, job);
    return 0;
}

static void process_result(zmq_msg_t* msg) {
    if (zmq_msg_size(msg) == 0)
        return;

    json_error_t errobj;

    json_t* payload = json_loadb(zmq_msg_data(msg), zmq_msg_size(msg), 0, &errobj);
    if (payload == NULL) {
        logit(NSLOG_RUNTIME_WARNING, FALSE,
            "NagMQ received a command, but it wasn't valid JSON. %s at position %d",
            errobj.text, errobj.position);
        return;
    }

    char* id;
    if (get_values(payload, "command_id", &id, NULL) != 0) {
        logit(NSLOG_RUNTIME_WARNING, FALSE, "NagMQ received a command that was missing an ID field");
        json_decref(payload);
        return;
    }

    struct job* job = NULL;
    HASH_FIND_STR(jobs, id, job);

    process_check_status(payload);
    json_decref(payload);

    if (job) {
        free_job(job);
    }
}

int handle_startup(json_t* config, void* sock) {
    command_sock = sock;
    neb_register_callback(NEBCALLBACK_HOST_CHECK_DATA, handle, 0, handle_command_data);
    neb_register_callback(NEBCALLBACK_SERVICE_CHECK_DATA, handle, 0, handle_command_data);
    neb_register_callback(NEBCALLBACK_EVENT_HANDLER_DATA, handle, 0, handle_command_data);
}
