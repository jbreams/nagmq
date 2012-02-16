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

print "Starting event loop"
while True:
	type, pstr = sub.recv_multipart()
	payload = json.loads(pstr)
	msg = None
	if('service_description' in payload):
		state = None
		if(payload['state'] == 0):
			state = 'OK'
		elif(payload['state'] == 1):
			state = 'WARNING'
		elif(payload['state'] == 2):
			state = 'CRITICAL'
		elif(payload['state'] == 3):
			state = 'UNKNOWN'
		msg = "{0}@{1} {2}: {3}".format(
			payload['service_description'],
			payload['host_name'],
			state, payload['output'])
	else:
		state = None
		if(payload['state'] < 2):
			state = 'UP'
		else:
			state = 'DOWN'
		msg = "{0} {2}: {3}".format(
			payload['host_name'], state,
			payload['output'])
	print msg
	try:
		api.update_status(msg)
	except TweepError as te:
		print "Could not post {0}: {1}".format(msg, te.reason)
