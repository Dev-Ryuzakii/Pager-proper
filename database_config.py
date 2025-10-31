"""
PostgreSQL Database Configuration
Settings and utilities for database connections
"""

import os
import re
import time
from typing import Optional
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from database_models import Base
import logging

logger = logging.getLogger(__name__)

class DatabaseConfig:
    """Database configuration class"""
    
    def __init__(self):
        # Connection pool settings (set these first)
        self.POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
        self.MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        self.POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
        self.POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))
        
        # Handle Render's DATABASE_URL environment variable
        database_url = os.getenv("DATABASE_URL")
        
        # Log all relevant environment variables for debugging
        logger.info("Environment variables:")
        for key, value in os.environ.items():
            if "DATABASE" in key.upper() or "DB_" in key.upper():
                # Don't log sensitive information
                if "PASSWORD" in key.upper() or "SECRET" in key.upper():
                    logger.info(f"  {key}: ***")
                else:
                    logger.info(f"  {key}: {value}")
        
        if database_url and database_url.strip():
            # Use Render's provided DATABASE_URL
            logger.info("Using Render DATABASE_URL")
            logger.info(f"Raw DATABASE_URL: {database_url}")
            
            # Validate and normalize the database URL
            self.DATABASE_URL = self._normalize_database_url(database_url)
            logger.info(f"Normalized DATABASE_URL: {self.DATABASE_URL}")
        else:
            # Fallback to individual environment variables
            logger.warning("DATABASE_URL not found or empty, using fallback configuration")
            self.DB_HOST = os.getenv("DB_HOST", "localhost")
            self.DB_PORT = os.getenv("DB_PORT", "5432")
            self.DB_NAME = os.getenv("DB_NAME", "secure_messaging")
            self.DB_USER = os.getenv("DB_USER", os.getenv("USER", "postgres"))  # Use system user as default
            self.DB_PASSWORD = os.getenv("DB_PASSWORD", "")  # Empty password for local development
            
            # Connection string
            self.DATABASE_URL = self._build_database_url()
            logger.info(f"Using fallback DATABASE_URL: {self.DATABASE_URL}")
        
        # Engine and session
        self.engine = None
        self.SessionLocal = None

    def _normalize_database_url(self, database_url: str) -> str:
        """Normalize database URL for proper connection"""
        # Handle common issues with database URLs
        normalized_url = database_url.strip()
        
        # Add postgresql:// prefix if missing
        if not normalized_url.startswith(("postgresql://", "postgres://")):
            normalized_url = "postgresql://" + normalized_url
        
        # Replace postgres:// with postgresql:// if needed
        if normalized_url.startswith("postgres://"):
            normalized_url = "postgresql://" + normalized_url[11:]
        
        # Add SSL requirement for Render if not already present
        if "render.com" in normalized_url and "sslmode=" not in normalized_url:
            logger.info("Adding SSL requirement for Render database")
            if "?" in normalized_url:
                normalized_url += "&sslmode=require"
            else:
                normalized_url += "?sslmode=require"
        
        return normalized_url
    
    def _build_database_url(self) -> str:
        """Build database URL from configuration"""
        if hasattr(self, 'DB_PASSWORD') and self.DB_PASSWORD:
            return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        elif hasattr(self, 'DB_USER'):
            return f"postgresql://{self.DB_USER}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        else:
            # This case should not happen if DATABASE_URL is not set
            return "postgresql://postgres@localhost:5432/secure_messaging"
    
    def initialize_database(self, max_retries=3, retry_delay=5):
        """Initialize database engine and session factory with retry logic"""
        for attempt in range(max_retries):
            try:
                # Handle special case for Render's DATABASE_URL which might need SSL settings
                database_url = self.DATABASE_URL
                logger.info(f"Processing database URL: {database_url}")
                
                if "render.com" in database_url and "sslmode=require" not in database_url:
                    # Add SSL requirement for Render
                    logger.info("Adding SSL requirement for Render database")
                    if "?" in database_url:
                        database_url += "&sslmode=require"
                    else:
                        database_url += "?sslmode=require"
                    logger.info(f"Modified database URL: {database_url}")
                
                self.engine = create_engine(
                    database_url,
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
                
                logger.info(f"✅ Database connection initialized")
                return True
                
            except Exception as e:
                logger.error(f"❌ Failed to initialize database (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    return False
    
    def create_tables(self, max_retries=3, retry_delay=5):
        """Create all database tables with retry logic"""
        for attempt in range(max_retries):
            try:
                if not self.engine:
                    if not self.initialize_database():
                        return False
                        
                if self.engine:
                    Base.metadata.create_all(bind=self.engine)
                    logger.info("✅ Database tables created successfully!")
                    return True
                else:
                    logger.error("❌ Database engine not available")
                    return False
                    
            except Exception as e:
                logger.error(f"❌ Failed to create tables (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    return False
    
    def get_session(self) -> Optional[Session]:
        """Get a database session"""
        if not self.SessionLocal:
            if not self.initialize_database():
                return None
        if self.SessionLocal:
            return self.SessionLocal()
        return None
    
    def test_connection(self, max_retries=3, retry_delay=5):
        """Test database connection with retry logic"""
        for attempt in range(max_retries):
            try:
                if not self.engine:
                    logger.error("❌ Database engine not available for testing")
                    return False
                        
                logger.info("Attempting to connect to database...")
                with self.engine.connect() as connection:
                    result = connection.execute(text("SELECT 1"))
                    logger.info("✅ Database connection test successful!")
                    return True
                    
            except OperationalError as e:
                logger.error(f"❌ Database connection test failed (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    return False
            except Exception as e:
                logger.error(f"❌ Database connection test failed with unexpected error: {e}")
                logger.error(f"Error type: {type(e)}")
                return False

# Global database configuration instance
db_config = DatabaseConfig()

def get_database_session():
    """Dependency function for FastAPI to get database session"""
    session = db_config.get_session()
    if session:
        try:
            yield session
        finally:
            session.close()
    else:
        raise Exception("❌ Database session not available")

def init_database(max_retries=3, retry_delay=5):
    """Initialize database for the application with retry logic"""
    logger.info("🔧 Initializing PostgreSQL database...")
    
    # Initialize connection
    if not db_config.initialize_database(max_retries, retry_delay):
        logger.error("❌ Failed to initialize database connection")
        return False
    
    # Test connection
    if not db_config.test_connection(max_retries, retry_delay):
        logger.error("❌ Database connection test failed")
        return False
    
    # Create tables
    if not db_config.create_tables(max_retries, retry_delay):
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
    if hasattr(db_config, 'DATABASE_URL'):
        print(f"Database URL: {db_config.DATABASE_URL}")
    
    # Test initialization
    success = init_database()
    
    if success:
        print("\n🎉 Database setup completed successfully!")
        print("You can now use PostgreSQL with your secure messaging system.")
    else:
        print("\n❌ Database setup failed!")
        print("Please check your PostgreSQL installation and configuration.")