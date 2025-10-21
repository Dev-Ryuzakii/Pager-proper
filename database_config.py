"""
PostgreSQL Database Configuration
Settings and utilities for database connections
"""

import os
from typing import Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from database_models import Base
import logging

logger = logging.getLogger(__name__)

class DatabaseConfig:
    """Database configuration class"""
    
    def __init__(self):
        # Database connection settings
        self.DB_HOST = os.getenv("DB_HOST", "localhost")
        self.DB_PORT = os.getenv("DB_PORT", "5432")
        self.DB_NAME = os.getenv("DB_NAME", "secure_messaging")
        self.DB_USER = os.getenv("DB_USER", "postgres")
        self.DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
        
        # Connection pool settings
        self.POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
        self.MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        self.POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
        self.POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))
        
        # Connection string
        self.DATABASE_URL = self._build_database_url()
        
        # Engine and session
        self.engine = None
        self.SessionLocal = None
        
    def _build_database_url(self) -> str:
        """Build database URL from configuration"""
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    def initialize_database(self):
        """Initialize database engine and session factory"""
        try:
            self.engine = create_engine(
                self.DATABASE_URL,
                pool_size=self.POOL_SIZE,
                max_overflow=self.MAX_OVERFLOW,
                pool_timeout=self.POOL_TIMEOUT,
                pool_recycle=self.POOL_RECYCLE,
                echo=False  # Set to True for SQL debugging
            )
            
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            logger.info(f"✅ Database connection initialized: {self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
            return False
    
    def create_tables(self):
        """Create all database tables"""
        try:
            if not self.engine:
                self.initialize_database()
                
            Base.metadata.create_all(bind=self.engine)
            logger.info("✅ Database tables created successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create tables: {e}")
            return False
    
    def get_session(self) -> Session:
        """Get a database session"""
        if not self.SessionLocal:
            self.initialize_database()
        return self.SessionLocal()
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            if not self.engine:
                self.initialize_database()
                
            with self.engine.connect() as connection:
                result = connection.execute(text("SELECT 1"))
                logger.info("✅ Database connection test successful!")
                return True
                
        except Exception as e:
            logger.error(f"❌ Database connection test failed: {e}")
            return False

# Global database configuration instance
db_config = DatabaseConfig()

def get_database_session():
    """Dependency function for FastAPI to get database session"""
    session = db_config.get_session()
    try:
        yield session
    finally:
        session.close()

def init_database():
    """Initialize database for the application"""
    logger.info("🔧 Initializing PostgreSQL database...")
    
    # Initialize connection
    if not db_config.initialize_database():
        logger.error("❌ Failed to initialize database connection")
        return False
    
    # Test connection
    if not db_config.test_connection():
        logger.error("❌ Database connection test failed")
        return False
    
    # Create tables
    if not db_config.create_tables():
        logger.error("❌ Failed to create database tables")
        return False
    
    logger.info("🎉 Database initialization completed successfully!")
    return True

if __name__ == "__main__":
    # Test database setup when run directly
    logging.basicConfig(level=logging.INFO)
    
    print("🧪 Testing PostgreSQL Database Configuration")
    print("=" * 50)
    
    # Show configuration
    print(f"Database Host: {db_config.DB_HOST}")
    print(f"Database Port: {db_config.DB_PORT}")
    print(f"Database Name: {db_config.DB_NAME}")
    print(f"Database User: {db_config.DB_USER}")
    print(f"Database URL: {db_config.DATABASE_URL.replace(db_config.DB_PASSWORD, '*****')}")
    
    # Test initialization
    success = init_database()
    
    if success:
        print("\n🎉 Database setup completed successfully!")
        print("You can now use PostgreSQL with your secure messaging system.")
    else:
        print("\n❌ Database setup failed!")
        print("Please check your PostgreSQL installation and configuration.")