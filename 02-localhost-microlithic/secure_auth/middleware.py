"""Middleware configuration and setup."""

import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

logger = logging.getLogger(__name__)


def setup_middleware(app: FastAPI, settings):
    """Setup all middleware for the FastAPI application."""
    
    # 1. Rate limiting (outermost)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per day", "200 per hour"]
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    
    # 2. CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://0.0.0.0:8080"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    
    # 3. Session middleware (innermost, closest to routes)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        max_age=3600,  # 1 hour
        same_site='lax',  # Important for OAuth redirects
        https_only=False,  # False for localhost development
        session_cookie='oauth_session',  # Explicit cookie name to avoid conflicts
        path='/'  # Ensure cookie is available for all paths
    )
    
    # 4. Add security headers middleware
    @app.middleware("http")
    async def security_headers_and_session_debug_middleware(request: Request, call_next):
        # Log incoming request info (without accessing session directly)
        logger.debug(f"Incoming request to {request.url.path}")
        
        response = await call_next(request)
        
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        
        csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval' *; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net;"
        response.headers['Content-Security-Policy'] = csp
        
        # Log outgoing response info (session access happens in route handlers after middleware)
        logger.debug(f"Outgoing response from {request.url.path}")
        
        return response
    
    return limiter


def setup_error_handlers(app: FastAPI, templates):
    """Setup error handlers for the application."""
    
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: HTTPException):
        """Custom 404 handler."""
        logger.warning(f"404 error: {request.url}")
        try:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error_code": 404, "error_message": "Page not found"},
                status_code=404
            )
        except:
            return HTMLResponse("Page not found", status_code=404)
    
    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception):
        """Custom 500 handler."""
        logger.error(f"500 error: {request.url} - {str(exc)}")
        return HTMLResponse(f"Internal server error: {str(exc)}", status_code=500)
