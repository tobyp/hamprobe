import datetime

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy import Column, ForeignKey, String, Integer, Text, DateTime
from sqlalchemy.schema import PrimaryKeyConstraint, UniqueConstraint#
from sqlalchemy.dialects import mysql

Base = declarative_base()

# HamnetDB schema

class Site(Base):
	__tablename__ = 'hamnet_site'
	id = Column(mysql.INTEGER(10, unsigned=True), nullable=False, autoincrement="auto", primary_key=True)
	name = Column(mysql.VARCHAR(100), nullable=False, key='name')
	callsign = Column(mysql.VARCHAR(100), nullable=False, key='callsign')
	longitude = Column(mysql.DOUBLE, nullable=False)
	latitude = Column(mysql.DOUBLE, nullable=False)
	elevation = Column(mysql.INTEGER(11), nullable=False)
	ground_asl = Column(mysql.INTEGER(11), nullable=False)
	no_check = Column(mysql.INTEGER(11), nullable=False)
	radioparam = Column(mysql.VARCHAR(200), nullable=False)
	inactive = Column(mysql.INTEGER(11), nullable=False)
	newCover = Column(mysql.TINYINT(1), nullable=False, default=0)
	hasCover = Column(mysql.INTEGER(1), nullable=False, default=0)
	comment = Column(mysql.TEXT, nullable=False)
	maintainer = Column(mysql.VARCHAR(200), nullable=False)
	rw_maint = Column(mysql.INTEGER(11), nullable=False)
	editor = Column(mysql.VARCHAR(100), nullable=False)
	edited = Column(mysql.DATETIME, nullable=False)
	version = Column(mysql.INTEGER(11), nullable=False)
	deleted = Column(mysql.INTEGER(11), nullable=False)

class Host(Base):
	__tablename__ = 'hamnet_host'
	id = Column(mysql.INTEGER(10, unsigned=True), nullable=False, autoincrement="auto", primary_key=True)
	name = Column(mysql.VARCHAR(100), nullable=False, key='name')
	ip = Column(mysql.VARCHAR(20), nullable=False, key='ip')
	rawip = Column(mysql.INTEGER(10, unsigned=True), nullable=False, key='rawip')
	mac = Column(mysql.VARCHAR(20), nullable=False)
	aliases = Column(mysql.VARCHAR(200), nullable=False)
	typ = Column(mysql.VARCHAR(20), nullable=False)
	radioparam = Column(mysql.VARCHAR(200), nullable=False)
	site = Column(mysql.VARCHAR(20), nullable=False, key='site')
	no_ping = Column(mysql.INTEGER(11), nullable=False)
	comment = Column(mysql.TEXT, nullable=False)
	maintainer = Column(mysql.VARCHAR(200), nullable=False)
	rw_maint = Column(mysql.INTEGER(11), nullable=False)
	editor = Column(mysql.VARCHAR(20), nullable=False)
	edited = Column(mysql.DATETIME, nullable=False)
	version = Column(mysql.INTEGER(11), nullable=False)
	deleted = Column(mysql.INTEGER(11), nullable=False)

class Edge(Base):
	__tablename__ = 'hamnet_edge'
	id = Column(mysql.INTEGER(10, unsigned=True), nullable=False, autoincrement="auto", primary_key=True)
	left_site = Column(mysql.VARCHAR(80), nullable=False, key='left_site')
	left_host = Column(mysql.VARCHAR(80), nullable=False)
	right_site = Column(mysql.VARCHAR(80), nullable=False, key='right_site')
	right_host = Column(mysql.VARCHAR(80), nullable=False)
	typ = Column(mysql.VARCHAR(80), nullable=False)
	radioparam = Column(mysql.VARCHAR(200), nullable=False)
	comment = Column(mysql.TEXT, nullable=False)
	editor = Column(mysql.VARCHAR(100), nullable=False)
	edited = Column(mysql.DATETIME, nullable=False)
	version = Column(mysql.INTEGER(11), nullable=False)
	deleted = Column(mysql.INTEGER(11), nullable=False)

# HamProbe schema

class Probe(Base):
	__tablename__ = 'hamprobe_probe'
	id = Column(String(32), primary_key=True)
	key = Column(String(32), nullable=False)
	created = Column(DateTime, nullable=False)
	target_script = Column(String(64), nullable=False)
	target_policy = Column(String(64), nullable=False)
	last_status = Column(DateTime, nullable=True)
	last_ip = Column(String(42), nullable=True)


def get_engine(config):
	engine = create_engine(config["DATABASE"])
	if 'sqlite' in engine.driver:
		@event.listens_for(Engine, "connect")
		def set_sqlite_pragma(dbapi_connection, connection_record):
			cursor = dbapi_connection.cursor()
			cursor.execute("PRAGMA foreign_keys=ON")
			cursor.close()
	Base.metadata.create_all(engine)
	return engine

def get_session(engine):
	Session = sessionmaker(bind=engine)
	return Session()
