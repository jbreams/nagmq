#include <stdint.h>
#include <jansson.h>
#include "mqexec.h"

static struct child_job * runningtable[2048];

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