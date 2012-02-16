#!/usr/bin/python26

import tweepy, zmq, json

keyfile = open('oauthkeys.json', 'r')
oakeys = json.load(keyfile)
keyfile.close()

auth = tweepy.OAuthHandler(oakeys['consumer_key'], oakeys['consumer_secret'])
auth.set_access_token(oakeys['access_token'], oakeys['access_secret'])

api = tweepy.API(auth)

zctx = zmq.Context()
sub = zctx.socket(zmq.SUB)
sub.connect("ipc:///tmp/nagmq.sock")
sub.setsockopt(zmq.SUBSCRIBE, 'statechange')

cache = ( )

print "Starting event loop"
while True:
	type, pstr = sub.recv_multipart()
	payload = json.loads(pstr)
	msg = None
	name = None
	state = None
	if('service_description' in payload):
		name = "{0}@{1}".format(
			payload['service_description'],
			payload['host_name'])
	else:
		name = payload['host_name']
	if(payload['state'] == payload['last_state']):
		print "Skipping {0} (duplicate)".format(name)
		continue
	if('service_description' in payload):
		if(payload['state'] == 0):
			state = 'OK'
		elif(payload['state'] == 1):
			state = 'WARNING'
		elif(payload['state'] == 2):
			state = 'CRITICAL'
		elif(payload['state'] == 3):
			state = 'UNKNOWN'
	else:
		if(payload['state'] < 2):
			state = 'UP'
		else:
			state = 'DOWN'
	msg = "{0} {1}: {2} ({3})".format(
		name, state, payload['output'],
		payload['timestamp']['tv_sec'])
	print msg
	try:
		api.update_status(msg)
	except Exception, e:
		print "Could not post {0}: {1}".format(msg, str(e))
