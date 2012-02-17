#!/usr/bin/python26

import tweepy, zmq, json, syslog

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

def send_tweet(msg, depth=0):
	if(depth = 2):
		return
	try:
		api.update_status(msg)
	except Exception, e:
		if(e.reason == 'Status is a duplicate'):
			msg += "({0})".format(
				payload['timestamp']['tv_sec'])
			send_tweet(msg, depth + 1)
		else:
			syslog.syslog(syslog.LOG_ERR, 
				"Could not post {0}: {1}".format(msg, str(e)))

syslog.syslog('Starting NagMQ Twitter event loop')
while True:
	type, pstr = sub.recv_multipart()
	payload = json.loads(pstr)
	msg = None
	name = None
	state = None
	if(payload['service_description'] != None):
		name = "{0}@{1}".format(
			payload['service_description'],
			payload['host_name'])
	else:
		name = payload['host_name']
	if(payload['state'] == payload['last_state']):
		continue
	if(payload['service_description'] != None):
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
	msg = "{0} {1}: {2}".format(
		name, state, payload['output'])
	send_tweet(msg)
