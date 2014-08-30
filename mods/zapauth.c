#include <zmq.h>
#include "json.h"
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include "nagios.h"

extern int keyfile_refresh_interval;
extern char * curve_knownhosts;
#if ZMQ_VERSION_MAJOR > 3
struct keybag {
	uint8_t key[32];
	struct keybag * next;
};

struct keybaghash {
	int buckets;
	int count;
	struct keybag ** data;
};

uint32_t fnv_hash(uint8_t * key) {
	int i;
	uint32_t hash = 2166136261; // offset_basis
	for(i = 0; i < 32; i++) {
		hash ^= key[i];
		hash *= 16777619; //fnv_prime
	}
	hash =(hash>>16) ^ (hash & 0xffff);

	return hash;
}

int rehash_keybags(struct keybaghash * o) {
	if(!(o->count > o->buckets && o->count < (0xffff)))
		return 0;

	int kiter;
	int newsize = ((o->buckets + 1) << 2) - 1;

	struct keybag ** newdata = calloc(newsize + 1, sizeof(struct keybag*));
	if(newdata == NULL)
		return -ENOMEM;

	for(kiter = 0; kiter < o->buckets + 1; kiter++) {
		struct keybag * curkey = o->data[kiter], *savekey;
		while(curkey) {
			uint32_t hash = fnv_hash(curkey->key) & newsize;
			savekey = curkey->next;
			curkey->next = newdata[hash];
			newdata[hash] = curkey;
			curkey = savekey;
		}
	}

	free(o->data);
	o->buckets = newsize;
	o->data = newdata;
	return 0;
}

int read_keyfile(const char * path, struct keybaghash * o) {
	char * buf = NULL;
	size_t buflen = 0;
	ssize_t readcount;
	int i;

	FILE * fp = fopen(path, "r");
	if(fp == NULL)
		return errno;

	for(i = 0; i < o->buckets; i++) {
		while(o->data[i]) {
			struct keybag * n = o->data[i]->next;
			free(o->data[i]);
			o->data[i] = n;
		}
	}
	o->count = 0;

	while((readcount = getline(&buf, &buflen, fp)) != -1) {
		char * end = buf + readcount, *front = buf;
		buflen = buflen > readcount ? buflen : readcount;

		while(front < end && isspace(*front))
			front++;
		if(*front == '\0' || *front == '#')
			continue;

		while(end - 1 > front && isspace(*(end - 1)))
			end--;
		if(isspace(*end))
			*end = '\0';
		end -= 40;

		if(end < front)
			continue;

		struct keybag * nk = calloc(1, sizeof(struct keybag));

		if(zmq_z85_decode(nk->key, end) == NULL) {
			free(nk);
			continue;
		}

		uint32_t hashval = fnv_hash(nk->key) & o->buckets;

		nk->next = o->data[hashval];
		o->data[hashval] = nk;
		o->count++;

		if(rehash_keybags(o) != 0)
			return -ENOMEM;
	}

	fclose(fp);
	free(buf);
	return 0;
}

int send_zap_resp(zmq_msg_t * reqid, char * code, char * text,
	char *user, void * sock) {
	int i = 0;

	struct tosend {
		char * val;
		size_t msgsize;
	} msgs[] = {
		{ "1.0", 3 },
		{ zmq_msg_data(reqid), zmq_msg_size(reqid) },
		{ code, strlen(code) },
		{ text, strlen(text) },
		{ user, strlen(user) },
		{ "", 0 },
		{ NULL, 0 }
	};

	for(i = 0; msgs[i].val != NULL; i++) {
		int flags = ZMQ_SNDMORE, rc;
		if(msgs[i + 1].val == NULL)
			flags = 0;
		rc = zmq_send(sock, msgs[i].val, msgs[i].msgsize, flags);
		if(rc == -1) {
			if(errno == ETERM)
				return -ETERM;
		}
	}

	return 0;
}

void * zap_handler(void* zapsock) {
	struct keybaghash bag;
	bag.buckets = 63;
	bag.data = calloc(64, sizeof(struct keybag*));
	bag.count = 0;
	time_t last_refresh = 0;
	int keeprunning = 1, i;
	sigset_t sigset;

	sigfillset(&sigset);
	pthread_sigmask(SIG_SETMASK, &sigset, NULL);

	log_debug_info(DEBUGL_IPC, DEBUGV_BASIC, "Starting NagMQ curve authentication thread\n");

	for(;;) {
		time_t now = time(NULL);
		int rc;
		if(rc = now - last_refresh > keyfile_refresh_interval) {
			if((rc = read_keyfile(curve_knownhosts, &bag)) != 0)
				logit(NSLOG_RUNTIME_ERROR, TRUE,
					"Error reading known hosts file for NagMQ curve authentication",
					strerror(rc));
			last_refresh = now;
			log_debug_info(DEBUGL_IPC, DEBUGV_BASIC,
				"Read known hosts file for NagMQ curve authentication\n");
		}

		zmq_msg_t reqid;
		char mech[32], creds[255];
		i = 0;

		zmq_msg_init(&reqid);
		for(i = 0; i < 7; i++) {
			zmq_msg_t curmsg;

			zmq_msg_init(&curmsg);
			rc = zmq_msg_recv(&curmsg, zapsock, 0);
			if(rc == -1) {
				if(errno == ETERM) {
					keeprunning = 0;
					break;
				}
				else
					break;
				logit(NSLOG_RUNTIME_ERROR, FALSE,
					"Error receiving NagMQ authentication packet");
			}

			if(i == 1) {
				size_t msglen = zmq_msg_size(&curmsg);
				zmq_msg_init_size(&reqid, msglen);
				memcpy(zmq_msg_data(&reqid), zmq_msg_data(&curmsg), msglen);
			}
			else if(i == 5)
				strncpy(mech, zmq_msg_data(&curmsg), zmq_msg_size(&curmsg));
			else if(i == 6)
				memcpy(creds, zmq_msg_data(&curmsg), zmq_msg_size(&curmsg));
			zmq_msg_close(&curmsg);
		}

		if(keeprunning == 0)
			break;
		else if(i < 7)
			continue;

		if(strcmp(mech, "CURVE") != 0) {
			rc = send_zap_resp(&reqid, "400",
				"Must use curve auth", "", zapsock);
			log_debug_info(DEBUGL_IPC, DEBUGV_BASIC,
				"NagMQ authentication request mechanism wasn't curve: %s\n", mech);
			goto cleanup;
		}

		uint32_t hashval = fnv_hash(creds);
		hashval &= bag.buckets;

		struct keybag * search = bag.data[hashval];

		while(search && memcmp(search->key, creds, 32) != 0)
			search = search->next;

		if(search == NULL) {
			rc = send_zap_resp(&reqid, "400",
				"No authorized key found", "", zapsock);
			log_debug_info(DEBUGL_IPC, DEBUGV_BASIC,
				"Client not found in NagMQ authorized keys file!\n");
			goto cleanup;
		}

		rc = send_zap_resp(&reqid, "200",
			"Authentication successful", "Authenticated User", zapsock);

		log_debug_info(DEBUGL_IPC, DEBUGV_BASIC,
			"Successfully authenticated client from authorized keys file!\n");
cleanup:
		zmq_msg_close(&reqid);
		if(rc == ETERM)
			break;
	}

	for(i = 0; i < bag.buckets; i++) {
		while(bag.data[i]) {
			struct keybag * n = bag.data[i]->next;
			free(bag.data[i]);
			bag.data[i] = n;
		}
	}

	log_debug_info(DEBUGL_IPC, DEBUGV_BASIC,
		"Ending NagMQ curve authentication thread\n");
	free(bag.data);
	zmq_close(zapsock);
	return NULL;
}
#endif