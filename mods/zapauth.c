#include "config.h"
#include "json.h"
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <zmq.h>
#ifdef HAVE_ICINGA
#include "icinga.h"
#else
#include "nagios.h"
#endif
#include "uthash.h"

extern char* curve_knownhosts;
#if ZMQ_VERSION_MAJOR > 3
struct key_data {
    uint8_t data[32];
};

struct allowed_key {
    struct key_data key;
    UT_hash_handle hh;
};

struct allowed_key* read_keyfile(const char* path) {
    char* buf = NULL;
    size_t buflen = 0;
    ssize_t readcount;

    FILE* fp = fopen(path, "r");
    if (fp == NULL) {
        logit(NSLOG_RUNTIME_ERROR,
              TRUE,
              "Error reading known hosts file for NagMQ curve authentication: %s",
              strerror(errno));
        return NULL;
    }

    struct allowed_key* keys = NULL;

    while ((readcount = getline(&buf, &buflen, fp)) != -1) {
        char *end = buf + readcount, *front = buf;
        buflen = buflen > readcount ? buflen : readcount;

        while (front < end && isspace(*front))
            front++;
        if (*front == '\0' || *front == '#')
            continue;

        while (end - 1 > front && isspace(*(end - 1)))
            end--;
        if (isspace(*end))
            *end = '\0';
        end -= 40;

        if (end < front)
            continue;

        struct allowed_key* nk = calloc(1, sizeof(struct allowed_key));
        if (zmq_z85_decode(nk->key.data, end) == NULL) {
            free(nk);
            continue;
        }

        HASH_ADD(hh, keys, key, sizeof(struct key_data), nk);
    }

    fclose(fp);
    free(buf);
    return keys;
}

int send_zap_resp(zmq_msg_t* reqid, char* code, char* text, char* user, void* sock) {
    int i = 0;

    struct tosend {
        char* val;
        size_t msgsize;
    } msgs[] = {{"1.0", 3},
                {zmq_msg_data(reqid), zmq_msg_size(reqid)},
                {code, strlen(code)},
                {text, strlen(text)},
                {user, strlen(user)},
                {"", 0},
                {NULL, 0}};

    for (i = 0; msgs[i].val != NULL; i++) {
        int flags = ZMQ_SNDMORE, rc;
        if (msgs[i + 1].val == NULL)
            flags = 0;
        rc = zmq_send(sock, msgs[i].val, msgs[i].msgsize, flags);
        if (rc == -1) {
            if (errno == ETERM)
                return -ETERM;
        }
    }

    return 0;
}

void* zap_handler(void* zapsock) {
    int keeprunning = 1, i, rc;
    sigset_t sigset;

    sigfillset(&sigset);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);

    log_debug_info(DEBUGL_IPC, DEBUGV_BASIC, "Starting NagMQ curve authentication thread\n");

    struct allowed_key* keys = read_keyfile(curve_knownhosts);
    if (!keys)
        return NULL;

    for (;;) {
        zmq_msg_t reqid;
        char mech[32], creds[255];
        i = 0;

        zmq_msg_init(&reqid);
        for (i = 0; i < 7; i++) {
            zmq_msg_t curmsg;

            zmq_msg_init(&curmsg);
            rc = zmq_msg_recv(&curmsg, zapsock, 0);
            if (rc == -1) {
                if (errno == ETERM) {
                    keeprunning = 0;
                    break;
                } else
                    break;
                logit(NSLOG_RUNTIME_ERROR, FALSE, "Error receiving NagMQ authentication packet");
            }

            if (i == 1) {
                size_t msglen = zmq_msg_size(&curmsg);
                zmq_msg_init_size(&reqid, msglen);
                memcpy(zmq_msg_data(&reqid), zmq_msg_data(&curmsg), msglen);
            } else if (i == 5)
                strncpy(mech, zmq_msg_data(&curmsg), zmq_msg_size(&curmsg));
            else if (i == 6)
                memcpy(creds, zmq_msg_data(&curmsg), zmq_msg_size(&curmsg));
            zmq_msg_close(&curmsg);
        }

        if (keeprunning == 0)
            break;
        else if (i < 7)
            continue;

        if (strcmp(mech, "CURVE") != 0) {
            rc = send_zap_resp(&reqid, "400", "Must use curve auth", "", zapsock);
            log_debug_info(DEBUGL_IPC,
                           DEBUGV_BASIC,
                           "NagMQ authentication request mechanism wasn't curve: %s\n",
                           mech);
            goto cleanup;
        }

        struct allowed_key needle, *found = NULL;
        memcpy(needle.key.data, creds, 32);
        HASH_FIND(hh, keys, &needle.key, sizeof(struct key_data), found);

        if (found == NULL) {
            rc = send_zap_resp(&reqid, "400", "No authorized key found", "", zapsock);
            log_debug_info(
                DEBUGL_IPC, DEBUGV_BASIC, "Client not found in NagMQ authorized keys file!\n");
            goto cleanup;
        }

        rc = send_zap_resp(
            &reqid, "200", "Authentication successful", "Authenticated User", zapsock);

        log_debug_info(DEBUGL_IPC,
                       DEBUGV_BASIC,
                       "Successfully authenticated client from authorized keys file!\n");
    cleanup:
        zmq_msg_close(&reqid);
        if (rc == ETERM)
            break;
    }

    log_debug_info(DEBUGL_IPC, DEBUGV_BASIC, "Ending NagMQ curve authentication thread\n");
    HASH_CLEAR(hh, keys);
    zmq_close(zapsock);
    return NULL;
}
#endif
