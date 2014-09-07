import yaml
import zmq
try:
	import simplejson as json
except ImportError:
	import json
import sys
from pymongo import MongoClient
from eventhandlers import event_map, process_event
import logging

logger = logging.getLogger('nagmq-collector')

def parse_config(config_path, zmqctx):
	with open(config_path, 'r') as config_fp:
		logger.debug("Loading config file {0}".format(config_path))
		config = yaml.load(config_fp)
		if 'mongouri' not in config:
			print "No MongoDB URI specified in config. Cannot continue."
			exit(1)

	dbconn = MongoClient(config['mongouri'])
	logger.debug("Connecting to mongodb at {0}".format(config['mongouri']))

	if 'eventsource' not in config:
		print "No event source defined in config. Cannot continue."
		exit(1)
	sock = zmqctx.socket(zmq.SUB)
	if 'curve' in config:
		logger.debug("Setting up Curve security")
		if 'serverkey' not in config['curve']:
			logger.error("Specified a curve config, but didn't specify a server key.")
			exit(1)
		sock.setsockopt(zmq.CURVE_SERVERKEY, config['curve']['serverkey'])
		if 'secretkey' not in config['curve']:
			logger.error("Specified a curve config, but didn't specify a secret key.")
			exit(1)
		sock.setsockopt(zmq.CURVE_SECRETKEY, config['curve']['secretkey'])
		if 'publickey' not in config['curve']:
			logger.error("Specified a curve config, but didn't specify a public key.")
			exit(1)
		sock.setsockopt(zmq.CURVE_PUBLICKEY, config['curve']['publickey'])

	sock.setsockopt(zmq.IMMEDIATE, True)
	logger.debug("Connecting to {0}".format(config['eventsource']))
	sock.connect(config['eventsource'])
	sublist = event_map.keys()
	if 'subscription_list' in config:
		sublist = config['subscription_list']
	for s in sublist:
		logger.debug("Subscribing to {0}".format(s))
		sock.setsockopt(zmq.SUBSCRIBE, s)

	return (sock, dbconn)

def main(config_path):
	logger.debug("Starting up")
	zmqctx = zmq.Context()
	(eventsock, dbconn) = parse_config(config_path, zmqctx)
	dbhandle = dbconn.get_default_database()
	if not dbhandle:
		logger.error("No database was specified in MongoDB URI. Cannot continue.")
		exit(1)

	while True:
		fullmsg = eventsock.recv_multipart()
		logger.debug("Received event {0}".format(fullmsg[0]))
		eventobj = json.loads(fullmsg[1])
		process_event(eventobj, dbhandle)
