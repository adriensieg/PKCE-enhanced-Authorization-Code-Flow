"""Configuration module for OAuth authentication."""

import os
import logging
from typing import Optional
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
try:
    from dotenv import load_dotenv
    # Load from .env file in project root
    env_path = Path(__file__).parent.parent / '.env'
    load_dotenv(dotenv_path=env_path)
    logger.info(f"Environment variables loaded from {env_path}")
except ImportError:
    logger.warning("python-dotenv not available, using system environment")


class Settings:
    """Application settings and configuration."""
    
    def __init__(self):
        # OAuth Configuration - now from environment variables
        self.TENANT_ID = os.getenv('TENANT_ID')
        self.CLIENT_ID = os.getenv('CLIENT_ID')
        self.CLIENT_SECRET = os.getenv('CLIENT_SECRET')
        self.REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:8080/auth/callback')
        
        # Auto-generate SECRET_KEY if not provided (development only)
        self.SECRET_KEY = os.getenv('SECRET_KEY')
        if not self.SECRET_KEY:
            import secrets
            self.SECRET_KEY = secrets.token_urlsafe(32)
            logger.warning("SECRET_KEY not found in environment - auto-generated (not recommended for production!)")
        
        # Validate required settings (SECRET_KEY is now optional with auto-generation)
        required = ['TENANT_ID', 'CLIENT_ID', 'CLIENT_SECRET']
        missing = [key for key in required if not getattr(self, key)]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
        
        # Microsoft Entra ID endpoints
        self.AUTHORIZATION_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/authorize'
        self.TOKEN_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/token'
        self.JWKS_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/discovery/v2.0/keys'
        self.LOGOUT_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/logout'
        
        # Application settings
        self.PORT = int(os.getenv("PORT", 8080))
        self.HOST = os.getenv("HOST", "localhost")
        
        # Log configuration (without exposing secrets)
        logger.info(f"OAuth Configuration loaded - Tenant: {self.TENANT_ID}")
        logger.info(f"Client ID: {self.CLIENT_ID[:8]}..." if self.CLIENT_ID else 'NOT_SET')
        logger.info(f"Redirect URI: {self.REDIRECT_URI}")
        logger.info(f"Secret Key: {'SET' if self.SECRET_KEY else 'NOT_SET'}")


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings