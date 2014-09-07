
from datetime import datetime
from bson import objectid
import logging

logger = logging.getLogger('nagmq-collector')

class EventBase:
    timestamp_keys = set()
    def __init__(self, objectin):
        self.event_object = objectin
        for i in self.event_object.keys():
            if isinstance(self.event_object[i], dict) and 'tv_sec' in self.event_object[i]:
                timestampval = datetime.fromtimestamp(
                    self.event_object[i]["tv_sec"] + 
                    self.event_object[i]["tv_usec"] / 1000000
                )
                self.event_object[i] = timestampval
            if i in self.timestamp_keys:
                self.event_object[i] = datetime.fromtimestamp(self.event_object[i])
        pass

    def event_collection(self):
        return None

    def event_user(self):
        return "(N/A)"

    def event_status(self):
        return "(N/A)"

    def event_objectname(self):
        if 'host_name' not in self.event_object:
            return None
        if 'service_description' in self.event_object and \
            self.event_object['service_description'] != None:
            return "{0} @ {1}".format(
                self.event_object['service_description'],
                self.event_object['host_name']
            )
        else:
            return "Host Check @ {0}".format(
                self.event_object['host_name']
            )

    def __str__(self):
        raise NotImplementedError

    def insert(self, dbconn):
        detail_record = { "_id": None }
        coll = self.event_collection()

        if coll:
            detail_record = self.event_object.copy()
            detail_record["_id"] = objectid.ObjectId()
            dbconn[coll].insert(detail_record)
            logger.debug("Inserting detail record {0} into {1}".format(
                detail_record["_id"],
                coll
            ))

        dbconn.events.insert({
            "timestamp": self.event_object['timestamp'],
            "details": detail_record["_id"],
            "collection": self.event_collection(),
            "string": str(self),
            "status": self.event_status(),
            "object_name": self.event_objectname(),
            "user": self.event_user()
        })
        logger.debug("Inserting event record: {0}".format(str(self)))

class EventLoopEndEvent(EventBase):
    def __str__(self):
        return "Nagios event loop has stopped"

class StateChangeEvent(EventBase):
    timestamp_keys = set(['last_check', 'last_state_change'])
    def event_collection(self):
        return "statechanges"

    def event_status(self):
        state = self.event_object["state_str"]
        if self.event_object["state_type"] == 1:
            state += " (HARD)"
        else:
            state += " (SOFT)"
        return state

    def __str__(self):
        return "{0} changed from {1} to {2}".format(
            self.event_objectname(),
            self.event_object["last_state_str"],
            self.event_status()
        )

class CommentEvent(EventBase):
    timestamp_keys = set(['entry_time', 'expire_time'])

    def event_collection(self):
        return "comments"

    def event_user(self):
        return self.event_object["author_name"]

    def __str__(self):
        return "{0} added a comment to {1}".format(
            self.event_user(),
            self.event_objectname()
        )

class DowntimeAddEvent(EventBase):
    timestamp_keys = set(['start_time', 'end_time', 'entry_time'])

    def event_collection(self):
        return "downtimes"

    def event_user(self):
        return self.event_object["author_name"]

    def __str__(self):
        return "{0} added downtime to {1}".format(
            self.event_user(),
            self.event_objectname()
        )

class DowntimeStartEvent(EventBase):
    def __init__(self, objectin):
        copyfields = [ "type", "host_name", "service_description", "downtime_id" ]
        newobj = dict([ (x, y) for (x, y) in objectin.items() if x in copyfields ])
        self.event_object = newobj

    def event_collection(self):
        return "downtimeevents"

    def __str__(self):
        return "Downtime started for {0}".format(self.event_objectname())

class DowntimeStopEvent(EventBase):
    def __init__(self, objectin):
        copyfields = [ "type", "host_name", "service_description", "downtime_id" ]
        newobj = dict([ (x, y) for (x, y) in objectin.items() if x in copyfields ])
        self.event_object = newobj

    def event_collection(self):
        return "downtimeevents"

    def __str__(self):
        return "Downtime stopped for {0}".format(self.event_objectname())

class DowntimeDeleteEvent(EventBase):
    def __init__(self, objectin):
        copyfields = [ "type", "host_name", "service_description", "downtime_id" ]
        newobj = dict([ (x, y) for (x, y) in objectin.items() if x in copyfields ])
        self.event_object = newobj

    def event_collection(self):
        return "downtimeevents"

    def __str__(self):
        return "Downtime was deleted for {0}".format(self.event_objectname())

class NotificationEvent(EventBase):
    timestamp_keys = set(['last_check', 'last_state_change', 'last_notification'])
    def event_collection(self):
        return "notifications"

    def __str__(self):
        nottype = "A notification"
        if self.event_object["escalated"]:
            nottype = "An escalated notification"
        return "{0} was sent for {1}".format(
            nottype,
            self.event_objectname()
        )

class FlappingStartEvent(EventBase):
    def event_collection(self):
        return "flappingevents"

    def __str__(self):
        return "{0} started to flap".format(self.event_objectname())

class FlappingStopEvent(EventBase):
    def event_collection(self):
        return "flappingevents"

    def __str__(self):
        return "{0} stopped flapping".format(self.event_objectname())

class AdaptiveChangeEvent(EventBase):
    def event_collection(self):
        return "adaptivechanges"

    def __str__(self):
        return "{0} changed for {1}".format(
            self.event_object["attr"],
            self.event_objectname()
        )

class AcknowledgementEvent(EventBase):
    def event_collection(self):
        return "acknowledgements"

    def event_user(self):
        return self.event_object["author_name"]

    def __str__(self):
        return "{0} acknowledged problem on {1}".format(
            self.event_user(),
            self.event_objectname()
        )

class CheckResultEvent(EventBase):
    timestamp_keys = set(['last_check', 'last_state_change'])
    def event_collection(self):
        return "checkresults"

    def event_status(self):
        return self.event_object['state_str']

    def __str__(self):
        return "{0} returned a check result".format(
            self.event_objectname()
        )

event_map = {
    'acknowledgement': AcknowledgementEvent,
    'adaptiveservice_update': AdaptiveChangeEvent,
    'adaptivehost_update': AdaptiveChangeEvent,
    'flapping_stop': FlappingStopEvent,
    'flapping_start': FlappingStartEvent,
    'notification_start': NotificationEvent,
    'downtime_add': DowntimeAddEvent,
    'downtime_delete': DowntimeDeleteEvent,
    'downtime_start': DowntimeStartEvent,
    'downtime_stop': DowntimeStopEvent,
    'comment_add': CommentEvent,
    'statechange': StateChangeEvent,
    'eventloopend': EventLoopEndEvent,
    'host_check_processed': CheckResultEvent,
    'service_check_processed': CheckResultEvent
}

def process_event(objectin, dbconn):
    if objectin['type'] not in event_map:
        return

    event_obj = event_map[objectin['type']](objectin)
    event_obj.insert(dbconn)
