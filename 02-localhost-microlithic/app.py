"""Main FastAPI application with modular authentication."""

import os
import sys
import logging
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, Any

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import authentication library components
from secure_auth import get_settings, StateStore, JWKSCache, setup_middleware, setup_error_handlers
from secure_auth.routes import auth_router, debug_router
from secure_auth.sessions import get_user_from_session
from secure_auth.dependencies import get_current_user

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Secure OAuth Application",
    description="OAuth 2.0 with PKCE implementation using Microsoft Entra ID",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize configuration and stores
settings = get_settings()
state_store = StateStore()
jwks_cache = JWKSCache()

# Store in app state for access in routes
app.state.settings = settings
app.state.state_store = state_store
app.state.jwks_cache = jwks_cache

# Templates
templates = Jinja2Templates(directory="templates")
app.state.templates = templates

# Setup middleware
limiter = setup_middleware(app, settings)

# Setup error handlers
setup_error_handlers(app, templates)

# Include authentication routes
app.include_router(auth_router)
app.include_router(debug_router)


# Application-specific routes
@app.get("/", response_class=HTMLResponse)
@limiter.limit("100 per minute")
async def home(request: Request):
    """Home page - shows user info if authenticated."""
    try:
        # Enhanced session debugging
        logger.debug(f"Home page - Session available: {hasattr(request, 'session')}")
        logger.debug(f"Home page - Session keys: {list(request.session.keys()) if hasattr(request, 'session') else 'No session'}")
        logger.debug(f"Home page - Session data: {dict(request.session) if hasattr(request, 'session') else 'No session'}")
        
        user = get_user_from_session(request, state_store)
        logger.info(f"Home page accessed - User: {'authenticated' if user else 'anonymous'}")
        
        return templates.TemplateResponse(
            "index.html", 
            {"request": request, "user": user}
        )
    except Exception as e:
        logger.error(f"Error in home route: {e}", exc_info=True)
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Error</title></head>
        <body>
            <h1>Application Error</h1>
            <p>Error: {str(e)}</p>
            <p><a href="/health">Health Check</a></p>
        </body>
        </html>
        """, status_code=500)


# Add any additional application-specific routes here
# @app.get("/your-feature")
# async def your_feature(request: Request, user: Dict[str, Any] = Depends(get_current_user)):
#     """Your new feature that requires authentication."""
#     pass
