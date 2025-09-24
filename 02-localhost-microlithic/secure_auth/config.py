"""Configuration module for OAuth authentication."""

import os
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Environment variables loaded from .env")
except ImportError:
    print("python-dotenv not available, using system environment")


class Settings:
    """Application settings and configuration."""
    
    def __init__(self):
        # OAuth Configuration
        self.TENANT_ID = ''
        self.CLIENT_ID = ''
        self.CLIENT_SECRET = ''
        self.REDIRECT_URI = ''
        self.SECRET_KEY = ''
        
        # Microsoft Entra ID endpoints
        self.AUTHORIZATION_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/authorize'
        self.TOKEN_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/token'
        self.JWKS_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/discovery/v2.0/keys'
        self.LOGOUT_URL = f'https://login.microsoftonline.com/{self.TENANT_ID}/oauth2/v2.0/logout'
        
        # Application settings
        self.PORT = int(os.getenv("PORT", 8080))
        self.HOST = "localhost"
        
        # Log configuration
        logger.info(f"OAuth Configuration loaded - Tenant: {self.TENANT_ID}")
        logger.info(f"Client ID: {self.CLIENT_ID[:8] if self.CLIENT_ID else 'NOT_SET'}...")
        logger.info(f"Redirect URI: {self.REDIRECT_URI}")
        logger.info(f"Secret Key: {'SET' if self.SECRET_KEY else 'NOT_SET'}")


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create application settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
