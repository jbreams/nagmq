from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class Checkable(Base):
	__tablename__ = "checkables"
	id = Column(Integer, autoincrement=True, primary_key=True)
	host_name = Column(String, index=True)
	service_description = Column(String, index=True)

def resolve_checkable(o, session):
	ret = None
	if 'service_description' not in o:
		ret = session.query(Checkable.id). \
			filter(Checkable.host_name == o['host_name']).first()
	else:
		ret = session.query(Checkable.id). \
			filter(Checkable.host_name == o['host_name']). \
			filter(Checkable.service_description == o['service_description']).first()
	if ret:
		return ret[0]
	return None

def global_init(self, o, session):
	self.checkable = resolve_checkable(o, session)
	if not self.checkable:
		c = Checkable(id=None,
			host_name=o['host_name'],
			service_description=o['service_description'])
		session.add(c)
		session.commit()
		self.checkable = c.id
	print self.checkable
	for k in o:
		if not hasattr(self, k):
			continue
		setattr(self, k, o[k])

class Acknowledgement(Base):
	__tablename__ = "acknowledgements"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	state = Column(String)
	acknowledgement_type = Column(Integer)
	author_name = Column(String)
	comment_data = Column(String)
	is_sticky = Column(Boolean)
	persistent_comment = Column(Boolean)
	notify_contacts = Column(Boolean)

	__init__ = global_init

class StateChange(Base):
	__tablename__ = "statechanges"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	state = Column(String)
	state_type = Column(Integer)
	current_attempt = Column(Integer)
	max_attempts = Column(Integer)
	output = Column(String)
	last_state = Column(String)
	last_hard_state = Column(String)
	last_state_change = Column(DateTime)
	is_flapping = Column(Boolean)
	timestamp = Column(DateTime)
	problem_has_been_acknowledged = Column(Boolean)

	__init__ = global_init

class Comment(Base):
	__tablename__ = "comments"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	author_name = Column(String)
	comment_data = Column(String)
	persistent = Column(Boolean)
	expires = Column(Boolean)
	expire_time = Column(DateTime)
	timestamp = Column(DateTime)
	comment_id = Column(Integer)

	__init__ = global_init

class Downtime(Base):
	__tablename__ = "downtimes"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	author_name = Column(String)
	comment_data = Column(String)
	start_time = Column(DateTime)
	end_time = Column(DateTime)
	fixed = Column(Boolean)
	duration = Column(Integer)
	downtime_id = Column(Integer, index=True)
	timestamp = Column(DateTime)

	__init__ = global_init

class DowntimeEvent(Base):
	__tablename__ = "downtime_events"
	id = Column(Integer, autoincrement=True, primary_key=True)
	event_type = Column(String, primary_key=True)
	downtime_id = Column(Integer)
	timestamp = Column(DateTime)

	__init__ = global_init

class Notification(Base):
	__tablename__ = "notifications"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	state = Column(String)
	last_state = Column(String)
	last_hard_state = Column(String)
	last_state_change = Column(DateTime)
	last_check = Column(DateTime)
	output = Column(String)
	ack_author = Column(String)
	ack_data = Column(String)
	escalated = Column(Boolean)
	contacts_notified = Column(Boolean)
	timestamp = Column(DateTime)

	__init__ = global_init

class FlappingEvent(Base):
	__tablename__ = "flapping_events"
	id = Column(Integer, autoincrement=True, primary_key=True)
	event_type = Column(String)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	comment_id = Column(Integer)

	__init__ = global_init

class AdaptiveChange(Base):
	__tablename__ = "adaptive_changes"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	attr = Column(String)
	value = Column(Boolean)

	def __init__(self, obj):
		self.checkable = resolve_checkable(obj)
		self.attr = obj['attr']
		self.value = obj[obj['attr']]

class EventHandler(Base):
	__tablename__ = "eventhandlers"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	state = Column(String)
	last_state = Column(String)
	last_hard_state = Column(String)
	last_state_change = Column(DateTime)
	last_check = Column(DateTime)
	command_name = Column(String)
	command_args = Column(String)
	command_line = Column(String)

	__init__ = global_init

class NagiosEvent(Base):
	__tablename__ = "events"
	id = Column(Integer, autoincrement=True, primary_key=True)
	checkable = Column(Integer, ForeignKey("checkables.id"))
	table = Column(String)
	foreignid = Column(Integer)

	def __init__(self, row):
		self.checkable = row.checkable
		self.table = row.__tablename__
		self.foreignid = row.id

def build_row(o, session):
	datefields = [ 'end_time', 'expire_time', 'last_check',
		'last_state_change', 'start_time', 'timestamp' ]

	for k in datefields:
		if k not in o:
			continue
		if type(o[k]) is dict:
			o[k] = datetime.datetime.fromtimestamp(o[k]['tv_sec'])
		else:
			o[k] = datetime.datetime.fromtimestamp(o[k])

	type_map = {
		'flapping_start': AdaptiveChange,
		'flapping_stop': AdaptiveChange,
		'notification_start': Notification,
		'downtime_start': DowntimeEvent,
		'downtime_stop': DowntimeEvent,
		'downtime_add': Downtime,
		'comment_add': Comment,
		'statechange': StateChange,
		'acknowledgement': Acknowledgement,
		'event_handler_start': EventHandler,
		'adaptiveservice_update': AdaptiveChange,
		'adaptivehost_update': AdaptiveChange
	}

	if o['type'] not in type_map:
		return None

	t = type_map[o['type']]
	return t(o, session)

def setup_tables(engine):
	Base.metadata.create_all(engine)
