NagMQ Collector
===============

The NagMQ collector takes all the events from the NagMQ events publisher and
writes them to MongoDB. Each class of event has its own collection, where the
NagMQ event document gets stored essentially verbatim, and an events collection
where a user friendly description of each even gets stored.

It runs as a python process called collectord which requires a yaml config file
like the one below
```
mongouri: mongodb://localhost:27017/nagiosdb
eventsource: tcp://localhost:5555
curve:
  # These are example keys. Place your own curve keys here
  serverkey: "@QxA0C]V9/xwyF?yrLuzJgB4:>lTetaO(EYM%5eD"
  publickey: "M1[UsNhTl$p5h:]n{yrb(0qZIp+^=oLbeiueJjjG"
  secretkey: "tGn4Lk%@VnZc#.rlAofGPu/Y.&!H@Ew5B3!w.4tt"
```

All documents inserted into MongoDB have a timestamp field, which cooresponds
to the time NagMQ published the event. If you want to limit the number of documents
stored, you can either make the [collections capped](http://docs.mongodb.org/manual/core/capped-collections/) (i.e. a ringbuffer), or you
can set a [ttl index](http://docs.mongodb.org/manual/core/index-ttl/).