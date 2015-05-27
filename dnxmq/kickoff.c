#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdint.h>
#include <fcntl.h>
#include <pwd.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>
#include <wordexp.h>
#include <time.h>
#include "mqexec.h"

extern char * unprivpath, *rootpath;
extern size_t unprivpathlen, rootpathlen;
extern uid_t runas;
extern uint32_t runningjobs;

int check_jail(const char * cmdline) {
	if(!unprivpath && !rootpath)
		return 1;
	if(rootpath && strncmp(cmdline, rootpath, rootpathlen) == 0)
		return 1;
	else if(unprivpath && strncmp(cmdline, unprivpath, unprivpathlen) == 0)
		return 2;
	return 0;
}

// Taken from http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
/* Subtract the `struct timeval' values X and Y,
storing the result in RESULT.
Return 1 if the difference is negative, otherwise 0. */

int
timeval_subtract (result, x, y)
struct timeval *result, *x, *y;
{
/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

/* Compute the time remaining to wait.
  tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

void do_kickoff(struct ev_loop * loop, zmq_msg_t * inmsg) {
	json_t * input;
	struct child_job * j;
	char * type, *command_line, *hostname = NULL, *svcdesc = NULL;
	json_error_t err;
	int fds[2];
	pid_t pid;
	int timeout = 0, okay_to_run;
	struct timeval server_starttime = {0, 0}, latencytv = { 0, 0 };
	double server_latency = 0.0;

	input = json_loadb(zmq_msg_data(inmsg), zmq_msg_size(inmsg), 0, &err);
	zmq_msg_close(inmsg);
	if(input == NULL) {
		logit(ERR, "Error loading request from broker: %s (line %d col %d)",
			err.text, err.line, err.column);
		return;
	}

	if(json_unpack(input, "{ s:s }", "type", &type) != 0) {
		logit(ERR, "Job message doesn't have a type header");
		json_decref(input);
		return;
	}

	if(json_unpack(input, "{ s:s s?:i s?:s s?:s s:{ s:i s:i } s?:f}",
		"command_line", &command_line,
		"timeout", &timeout, "host_name", &hostname,
		"service_description", &svcdesc,
		"timestamp", "tv_sec", &server_starttime.tv_sec,
		"tv_usec", &server_starttime.tv_usec,
		"latency", &server_latency) != 0) {
		logit(ERR, "Error unpacking JSON payload during kickoff");
		json_decref(input);
		return;
	}

	if(match_filter(input) != 1) {
		logit(DEBUG, "Not running %s because of filtering", command_line);
		json_decref(input);
		return;
	}

	if(!svcdesc)
		svcdesc = "(none)";

	logit(DEBUG, "Received job from upstream: %s %s",
		type, command_line);

	j = calloc(1, sizeof(struct child_job));
	if(strcmp(type, "service_check_initiate") == 0)
		j->service = 1;
	else if(strcmp(type, "host_check_initiate") == 0)
		j->service = 0;
	else
		j->service = -1;
	j->input = input;
	j->type = type;
	j->host_name = hostname;
	j->service_description = svcdesc;

	okay_to_run = check_jail(command_line);
	if(okay_to_run == 0) {
		logit(ERR, "Refusing to execute job outside sandbox %s", command_line);
		obj_for_ending(j, "Command line outside sandbox", 3, 0, 0);
		free(j);
		json_decref(input);
		return;
	}

	if(pipe(fds) < 0 ||
		fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0) {
		logit(ERR, "Error creating pipe for %s: %s",
			command_line, strerror(errno));
		obj_for_ending(j, "Error creating pipe", 3, 0, 0);
		free(j);
		json_decref(input);
		return;
	}

	ev_io_init(&j->io, child_io_cb, fds[0], EV_READ);
	j->io.data = j;
	ev_io_start(loop, &j->io);

	gettimeofday(&j->start, NULL);
	pid = fork();
	if(pid == 0) {
		wordexp_t expvec;
		int dn = open("/dev/null", O_RDONLY);
		if(dn < 0) {
			printf("Error redirecting stdin: %s\n", strerror(errno));
			exit(127);
		}
		dup2(fds[1], fileno(stdout));
		dup2(fds[1], fileno(stderr));
		dup2(dn, fileno(stdin));
		close(dn);
		close(fds[1]);
#ifdef TEST
		printf("Testing testing testing!\n");
		exit(0);
#else

		if(geteuid() == 0 && runas != 0 && okay_to_run == 2)
			setuid(runas);

		switch(wordexp(command_line, &expvec, WRDE_NOCMD)) {
			case 0:
				break;
			case WRDE_SYNTAX:
				printf("Error executing \"%s\". Bad syntax\n", command_line);
				exit(127);
				break;
			case WRDE_CMDSUB:
				printf("Command \"%s\" uses unsafe command substitution.\n", command_line);
				exit(127);
				break;
			case WRDE_BADVAL:
			case WRDE_BADCHAR:
				printf("Command \"%s\" uses invalid characters or variables\n", command_line);
				exit(127);
				break;
			case WRDE_NOSPACE:
				printf("Out of memory while parsing command line\n");
				exit(127);
				break;
		}

		execv(expvec.we_wordv[0], expvec.we_wordv);
		printf("Error executing shell for %s: %m", command_line);
		exit(127);
#endif
	}
	else if(pid < 0) {
		logit(ERR, "Error forking for %s: %s",
			command_line, strerror(errno));
		obj_for_ending(j, "Error forking", 3, 0, 0);
		json_decref(input);
		ev_io_stop(loop, &j->io);
		close(fds[1]);
		close(fds[0]);
		free(j);
		return;
	}

	if(timeval_subtract(&latencytv, &j->start, &server_starttime) == 1 &&
		latencytv.tv_sec < -1) {
		logit(INFO, "Time skew detected in latency calculation: tv_sec: %d, tv_usec: %d",
			latencytv.tv_sec, latencytv.tv_usec);
	} else {
		server_latency += latencytv.tv_sec + (latencytv.tv_usec / 1000000.0);
		logit(DEBUG, "Network latency was %f seconds", server_latency);
	}
	j->latency = server_latency;

	j->pid = pid;
	add_child(j);
	close(fds[1]);

	if(timeout > 0) {
		ev_timer_init(&j->timer, child_timeout_cb, timeout, 0);
		j->timer.data = j;
		ev_timer_start(loop, &j->timer);
		j->timeout = timeout;
	}

	logit(DEBUG, "Kicked off %d for %s %s", pid, hostname, svcdesc);
	runningjobs++;
}
