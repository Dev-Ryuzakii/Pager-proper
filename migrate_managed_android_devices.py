"""Create Dilarion-managed Android device registration table."""

from sqlalchemy import create_engine

from database_config import get_database_url
from database_models import ManagedAndroidDevice


def migrate():
    engine = create_engine(get_database_url())
    ManagedAndroidDevice.__table__.create(bind=engine, checkfirst=True)


if __name__ == "__main__":
    migrate()
