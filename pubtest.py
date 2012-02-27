import zmq
import time
context = zmq.Context()

payload="{ \"host_name\": \"localhost\", \"current_attempt\": 1, \"max_attempts\": 5, \"state\": 0, \"last_state\": 0, \"last_hard_state\": 0, \"last_check\": 1329354262, \"last_state_change\": 1328881508, \"type\": \"host_check_processed\", \"start_time\": { \"tv_sec\": 1329354262, \"tv_usec\": 200794 }, \"end_time\": { \"tv_sec\": 1329354263, \"tv_usec\": 914919 }, \"early_timeout\": 0, \"execution_time\": 1.71412, \"latency\": 1.20000, \"return_code\": 0, \"output\": \"OK: 1 process matching 'cfexec' found,1 process matching 'cfserver' found,1 process matching 'cfrdsservice' found\", \"long_output\": null, \"perf_data\": null, \"timeout\": 60, \"timestamp\": { \"tv_sec\": 1329354264, \"tv_usec\": 313316 } }";
#payload="{ \"command_name\": \"stop_executing_host_checks\" }"

pub = context.socket(zmq.PUSH)
pub.connect("ipc:///tmp/nagmqpull.sock")
pub.send('host_check_processed', zmq.SNDMORE)
pub.send(payload)
print "Sent {0}".format(payload)
