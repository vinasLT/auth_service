from database.db.session import engine
from database.models import Base


def init_db():
    Base.metadata.create_all(bind=engine)
