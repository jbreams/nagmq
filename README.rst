NagMQ README
============

NagMQ_ is an event broker that exposes the internal state and events of
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

.. _`Apache Version 2 license`: http://www.apache.org/licenses/LICENSE-2.0.html
