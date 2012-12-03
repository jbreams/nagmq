from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
import tabledefs
import zmq
import simplejson as json

engine = create_engine('sqlite:///./tmpdb.db', echo=True)
tabledefs.setup_tables(engine)
Session = sessionmaker(bind=engine)
session = Session()

zctx = zmq.Context()
events = zctx.socket(zmq.SUB)
events.connect('EVENTS_ADDR')
events.setsockopt(zmq.SUBSCRIBE, '')

while True:
	typestr, payloadstr = events.recv_multipart()
	payload = json.loads(payloadstr)

	row = tabledefs.build_row(payload, session)
	if row:
		session.add(row)
		session.commit()
		event = tabledefs.NagiosEvent(row)
		session.add(event)
		session.commit()
