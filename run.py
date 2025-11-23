"""Entry point to run the OAuth application."""

import os
import logging
import uvicorn
from secure_auth import get_settings

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    settings = get_settings()
    
    logger.info("Starting Secure OAuth Application on localhost")
    logger.info(f"Configuration check:")
    logger.info(f"  TENANT_ID: {settings.TENANT_ID}")
    logger.info(f"  CLIENT_ID: {'SET' if settings.CLIENT_ID else 'NOT_SET'}")
    logger.info(f"  CLIENT_SECRET: {'SET' if settings.CLIENT_SECRET else 'NOT_SET'}")
    logger.info(f"  REDIRECT_URI: {settings.REDIRECT_URI}")
    logger.info(f"  Session Cookie: oauth_session")
    
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="debug",
        access_log=True,
        reload=True
    )