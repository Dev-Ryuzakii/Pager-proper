import logging
import sys
from sqlalchemy import create_engine
from database_config import get_database_url
from database_models import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate():
    url = get_database_url()
    logger.info(f"Connecting to database to create MDM tables...")
    
    engine = create_engine(url)
    # This will create tables that don't exist yet
    Base.metadata.create_all(bind=engine)
    
    logger.info("Database migration for MDMDeviceProfile complete.")

if __name__ == "__main__":
    migrate()
