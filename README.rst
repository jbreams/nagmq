NagMQ README
============

NagMQ is an event broker that exposes the internal state and events of
Nagios to endpoings on a ZeroMQ message bus.

Nagios objects and events are available as JSON. The broker exposes three
sockets, all of which are optional:

- Publisher - Publishes events coming out of the event broker in real-time

- Pull - Receives passive checks and commands, like the Nagios command pipe

- Request - Sends state data on demand to clients

There is a distributed DNX-style executor (mqexec) designed to have as many
workers (possibly at the edge as an NRPE-replacement) and job brokers as you
want. It can also submit its results to more than one Nagios instance. Each
worker can filter what checks it runs based on any field in the service/host
check and event handler initiate messages from the publisher.

It also comes with sample scripts written in Python to provide replacements
for nsca, nrpe, and a handy CLI which talk to the bus instead of status.dat.

NagMQ is licensed under the `Apache Version 2 license`_; see LICENSE in
the source distribution for details.

Visit https://groups.google.com/d/forum/nagmq for questions and announcements.

Requirements
------------

The NagMQ event broker requires the following libraries to compile
- jansson >= v2.4 (http://jansson.readthedocs.org)
- zeromq >= v2.2 (http://zeromq.org/)
- Nagios source/header files >= v3.1 (http://nagios.org)

The mqexec check executor requires the following additional libraries to compile
- pcre (optional) (http://www.pcre.org/)
- libev (http://software.schmorp.de/pkg/libev.html)

The utility python scripts included require
- pyzmq 

Depending on what version/flavor of Nagios you want to compile against, you will have to use one of the following configure flags::

	--with-icinga-headers=DIR
	--with-nagios3-headers=DIR
	--with-nagios4-src=DIR
	--with-naemon-src=DIR

NagMQ comes with some Nagios headers included, but their use is heavily deprecated and they will be removed very very soon. The Nagios sources need to be configured, but not built.

Support for Icinga and Naemon is experimental and not tested very well, so results may vary. If you're a big Icinga or Naemon user and find something wrong, pull requests are greatly appreciated!

If you are running Nagios 4, install the nagios-devel package to get the header files in /usr/include.

Compilation and Installation
----------------------------

Compile this from the Git repo by running::

	$ autoreconf -i
	$ ./configure --with-nagios4-src=/tmp/nagios-sources
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
			"bind": "ipc:///var/nagios/nagmqevents.sock",
			"override": [ "service_check_initiate", "host_check_initiate" ]
		},  
		"pull": {
			"bind": [ "ipc:///var/nagios/nagmqcommands.sock", "tcp://*:5556" ],
			"tcpacceptfilters": [ "localhost", "failoverhost" ]
		},  
		"reply": {
			"bind": [ "ipc:///var/nagios/nagmqstate.sock", "tcp://*:5557" ],
			"tcpacceptfilters": [ "localhost", "failoverhost" ]
		},  
   		"executor": {
    			"filter": { 
    				"match": "localhost",
    				"field": "host_name"},
			"jobs": "ipc:///var/nagios/mqexecjobs.sock",
			"results": "ipc:///var/nagios/mqexecresults.sock"
		},  
		"cli": {
			"pull": "tcp://localhost:5556",
			"reply": "tcp://localhost:5557"
		},  
		"devices": [
			[ { "backend": { "type": "push", "bind":"tcp://*:5558", "noblock":true,
				"tcpacceptfilters": [ "localhost", "failoverhost" ] },
				"frontend": { "type": "sub", "connect":"ipc:///var/nagios/nagmqevents.sock",
					"subscribe": [ "service_check_initiate", "host_check_initiate" ] } },
			{ "backend": { "type": "pull", "connect":"tcp://masterhost:5558" },
				"frontend": { "type":"push", "bind": "ipc:///var/nagios/mqexecjobs.sock" } },
			{ "backend": { "type": "push", "connect":"tcp://masterhost:5556" },
				"frontend": { "type":"pull", "bind": "ipc:///var/nagios/mqexecresults.sock" } } ]
		]   
	}


Start the dnxmq broker and worker:

    $ mqbroker /etc/nagios/nagmq.config
    $ mqexec /etc/nagios/nagmq.config

Restart Nagios, and you'll be able to connect to the message busses and
get data into and out of the broker!

If you do NOT wish to use dnxmq, remove the "override" directive from the
sample "publisher" config.

.. _`Apache Version 2 license`: http://www.apache.org/licenses/LICENSE-2.0.html
