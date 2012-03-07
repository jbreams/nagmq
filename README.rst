NagMQ README
============

NagMQ is an event broker that exposes the internal state and events of
Nagios to endpoings on a ZeroMQ message bus.

Nagios objects and events are available as JSON. The broker exposes three
sockets, all of which are optional:

- Publisher - Publishes events coming out of the event broker in real-time

- Pull - Receives passive checks and commands, like the Nagios command pipe

- Request - Sends state data on demand to clients

It also comes with sample scripts written in Python to provide replacements
for nsca, nrpe, and a handy CLI which talk to the bus instead of status.dat.

NagMQ is licensed under the `Apache Version 2 license`_; see LICENSE in
the source distribution for details.

Compilation and Installation
----------------------------

Compile this from the Git repo by running::

	$ ./configure
	$ make
	$ make install

Add the path to the installed broker to your nagios.cfg with the path to the
NagMQ config file as the broker parameter::

	# EVENT BROKER MODULE(S)
	...
	broker_module=/usr/local/lib/nagmq/nagmq.so /etc/nagios/nagmq.config
	#broker_module=/somewhere/module1.o
	#broker_module=/somewhere/module2.o arg1 arg2=3 debug=0

The NagMQ config file should be a JSON file that tells what message busses
the broker should connect/bind to. Each endpoint can connect and or bind
to any number of addresses - if you want to connect or bind to more than
one address, list them as an array.::

	{
		"publish": {
			"enable": true,
			"bind": [ "ipc:///tmp/nagmqpub.sock" ]
		},
		"pull": {
			"enable": true,
			"bind": "ipc:///tmp/nagmqpull.sock"
		},
		"reply": {
			"enable": true,
			"bind": "ipc:///tmp/nagmqreply.sock"
		}
	}

Restart Nagios, and you'll be able to connect to the message busses and
get data into and out of the broker!

.. _`Apache Version 2 license`: http://www.apache.org/licenses/LICENSE-2.0.html
