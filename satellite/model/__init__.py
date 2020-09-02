from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:///route.sqlite')
Base = declarative_base()
Base.metadata.create_all(engine)


class EntityAlreadyExists(BaseException):
    pass
