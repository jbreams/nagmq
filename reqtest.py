import zmq, time, json
context = zmq.Context()

pub = context.socket(zmq.REQ)
pub.connect("ipc:///tmp/nagmqreq.sock")
pub.send('{ "host_name": "localhost" }') #, "include_services": true, "include_contacts": true }')
resp = json.loads(pub.recv())
print resp
