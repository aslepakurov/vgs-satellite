from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, ARRAY
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class RouteManager:
    def __init__(self):
        engine = create_engine('sqlite:///route.sqlite')
        Session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        self.session = Session()

    def get_all(self):
        return self.session.query(Route).all()

    def get(self, route_id):
        return self.session.query(Route)\
            .filter(Route.id == route_id).one()

    def create(self):
        # self.session.add()
        pass

    def delete(self, route_id):
        self.session.query(Route)\
            .filter(Route.id == route_id).delete()
        self.session.commit()


class ModelMixin(object):

    def __repr__(self):
        attrs = ', '.join([
            '{0}={1}'.format(k, repr(v))
            for k, v in self.__dict__.items()
        ])
        return '{0}({1})'.format(self.__class__.__name__, attrs)


class Route(Base):
    __tablename__ = 'rule_chains'

    id = Column(String, primary_key=True)
    created_at = Column(DateTime)
    protocol = Column(String)
    source_endpoint = Column(String)
    destination_override_endpoint = Column(String)
    host_endpoint = Column(String)
    port = Column(Integer)
    tags = Column(JSON)
    rule_entries_list = relationship("RuleEntry", back_populates="rule_chain")

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat(),
            'protocol': self.protocol,
            'source_endpoint': self.source_endpoint,
            'destination_override_endpoint': self.destination_override_endpoint,
            'host_endpoint': self.host_endpoint,
            'port': self.port,
            'tags': self.tags,
            'entries': [entry.serialize for entry in self.rule_entries_list]
        }


class RuleEntry(Base):
    __tablename__ = 'rule_entries'

    id = Column(String, primary_key=True)
    created_at = Column(DateTime)
    route_id = Column(String, ForeignKey('rule_chains.id'))
    rule_chain = relationship("Route", back_populates='rule_entries_list')
    phase = Column(String)
    operation = Column(String)
    token_manager = Column(String)
    public_token_generator = Column(String)
    transformer = Column(String)
    transformer_config = Column(JSON)
    targets = Column(JSON)
    classifiers = Column(JSON)
    expression_snapshot = Column(JSON)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat(),
            'phase': self.phase,
            'token_manager': self.token_manager,
            'public_token_generator': self.public_token_generator,
            'transformer': self.transformer,
            'transformer_config': self.transformer_config,
            'operation': self.operation,
            'targets': self.targets,
            'classifiers': self.classifiers,
            'config': self.expression_snapshot
        }
