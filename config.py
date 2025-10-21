# FastAPI Configuration File
import os
from typing import Optional

class Settings:
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    
    # Security Configuration
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    
    # Database Files
    USER_KEYS_FILE: str = "user_keys_secure.json"
    OFFLINE_MESSAGES_FILE: str = "offline_messages.json"
    
    # TLS Server Integration
    TLS_SERVER_HOST: str = "127.0.0.1"
    TLS_SERVER_PORT: int = 5050
    
    # CORS Configuration
    CORS_ORIGINS: list = [
        "http://localhost:3000",  # React Native dev server
        "http://127.0.0.1:3000",
        "*"  # Allow all origins in development
    ]
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # File Upload
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    UPLOAD_DIR: str = "uploads"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "fastapi_mobile_backend.log"

# Global settings instance
settings = Settings()

# Environment-specific overrides
if os.getenv("PRODUCTION"):
    settings.DEBUG = False
    settings.SECRET_KEY = os.getenv("SECRET_KEY", settings.SECRET_KEY)
    settings.CORS_ORIGINS = ["https://yourdomain.com"]