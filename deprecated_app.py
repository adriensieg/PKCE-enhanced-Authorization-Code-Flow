import os
import logging
import secrets
import base64
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlencode, parse_qs

import requests
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.requests import Request as StarletteRequest
from jose import JWTError, jwt
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Secure OAuth Application",
    description="OAuth 2.0 with PKCE implementation using Microsoft Entra ID",
    version="1.0.0",
    docs_url="/docs" if os.getenv("ENVIRONMENT") == "development" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") == "development" else None
)

# Configuration
config = Config('.env')

# OAuth Configuration
# TENANT_ID = os.getenv('AZURE_TENANT_ID', 'common')
# CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
# CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
# REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://pretotype.com/auth/callback')
# SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))

# OAuth Configuration
# TENANT_ID = os.getenv('AZURE_TENANT_ID', 'common')
# CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
# CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
# REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:8080/auth/callback')  # Changed default
# SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-for-localhost-only')  # Dev default


TENANT_ID='df17274c-ffb6-45f7-84d3-177ae7c6bd1f'
CLIENT_ID='d95e0397-1de4-4434-a540-3aa5e3c73c94'
CLIENT_SECRET='5Mj8Q~IuFrRrnAuGeAWnEnmsQQSXZwOAmitc1csz'
REDIRECT_URI='http://localhost:8080/auth/callback'
SECRET_KEY='AN4nR-rN2XqbBi1cswvvg2T4RGYem_nVA-VZgSlxbpQ'

# Microsoft Entra ID endpoints
AUTHORIZATION_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize'
TOKEN_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token'
JWKS_URL = f'https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys'
LOGOUT_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/logout'

logger.info(f"OAuth Configuration loaded - Tenant: {TENANT_ID}, Client ID: {CLIENT_ID[:8]}...")

# Security middleware
# app.add_middleware(
    #SessionMiddleware,
    #secret_key=SECRET_KEY,
    #max_age=3600,  # 1 hour
    #same_site='strict',
    #https_only=True,
    #domain='pretotype.com'
#)

# Security middleware - MODIFIED FOR LOCALHOST
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=3600,  # 1 hour
    same_site='lax',  # Changed from 'strict' for localhost
    https_only=False,  # Changed to False for localhost HTTP
    # domain removed for localhost
)

# CORS middleware
#app.add_middleware(
    #CORSMiddleware,
    #allow_origins=["https://pretotype.com"],
    #allow_credentials=True,
    #allow_methods=["GET", "POST"],
    #allow_headers=["*"],
#)

# CORS middleware - MODIFIED FOR LOCALHOST
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "https://localhost:8080"],  # Localhost origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Trusted host middleware
#app.add_middleware(
    #TrustedHostMiddleware,
    #allowed_hosts=["pretotype.com", "*.pretotype.com"]
#)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "localhost:8080", "127.0.0.1:8080"]  # Localhost hosts
)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Templates
templates = Jinja2Templates(directory="templates")

# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy
    csp = {
        'default-src': ["'self'", "*.microsoft.com"],
        'style-src': ["'self'", "cdn.jsdelivr.net", "'unsafe-inline'"],
        'img-src': ["'self'", "cdn.jsdelivr.net", "data:"],
        'script-src': ["'self'", "cdn.jsdelivr.net"],
        'connect-src': ["'self'", "*.microsoft.com", "login.microsoftonline.com"],
        'font-src': ["'self'", "cdn.jsdelivr.net"],
        'object-src': ["'none'"],
        'media-src': ["'none'"],
        'frame-ancestors': ["'none'"]
    }
    
    csp_string = '; '.join([f"{key} {' '.join(values)}" for key, values in csp.items()])
    response.headers['Content-Security-Policy'] = csp_string
    
    return response

# PKCE helper functions
def generate_code_verifier() -> str:
    """Generate a cryptographically secure code verifier for PKCE."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(code_verifier: str) -> str:
    """Generate code challenge from verifier using SHA256."""
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

def generate_state() -> str:
    """Generate a secure state parameter for CSRF protection."""
    return secrets.token_urlsafe(32)

# Session helper functions
def get_user_from_session(request: Request) -> Optional[Dict[str, Any]]:
    """Get user information from session."""
    try:
        user_data = request.session.get('user')
        if user_data and isinstance(user_data, dict):
            # Check if session is still valid (within 1 hour)
            login_time = request.session.get('login_time')
            if login_time:
                login_datetime = datetime.fromisoformat(login_time)
                if datetime.utcnow() - login_datetime > timedelta(hours=1):
                    logger.info("Session expired, clearing user data")
                    request.session.clear()
                    return None
            return user_data
    except Exception as e:
        logger.error(f"Error getting user from session: {e}")
    return None

def clear_session(request: Request):
    """Clear all session data."""
    request.session.clear()
    logger.info("Session cleared")

# Authentication dependency
async def get_current_user(request: Request) -> Dict[str, Any]:
    """FastAPI dependency to get current authenticated user."""
    user = get_user_from_session(request)
    if not user:
        logger.warning("Unauthorized access attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user

# Token validation
async def validate_id_token(id_token: str) -> Dict[str, Any]:
    """Validate the ID token from Microsoft."""
    try:
        # For production, you should verify the signature using JWKS
        # For this example, we'll decode without verification
        # In production, use: jwt.decode(id_token, key, algorithms=['RS256'], audience=CLIENT_ID)
        
        # Get the unverified header and payload
        header = jwt.get_unverified_header(id_token)
        payload = jwt.get_unverified_claims(id_token)
        
        # Basic validation
        if payload.get('aud') != CLIENT_ID:
            raise ValueError("Invalid audience")
        
        if payload.get('exp', 0) < datetime.utcnow().timestamp():
            raise ValueError("Token expired")
        
        logger.info(f"ID token validated for user: {payload.get('preferred_username', 'unknown')}")
        return payload
        
    except Exception as e:
        logger.error(f"ID token validation failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid ID token")

# Routes
@app.get("/", response_class=HTMLResponse)
@limiter.limit("30 per minute")
async def home(request: Request):
    """Home page - shows user info if authenticated."""
    user = get_user_from_session(request)
    logger.info(f"Home page accessed - User: {'authenticated' if user else 'anonymous'}")
    
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "user": user}
    )

@app.get("/login", response_class=HTMLResponse)
@limiter.limit("10 per minute")
async def login_page(request: Request):
    """Login page."""
    user = get_user_from_session(request)
    if user:
        logger.info("Already authenticated user redirected from login page")
        return RedirectResponse(url="/", status_code=302)
    
    logger.info("Login page accessed")
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/auth/microsoft")
@limiter.limit("10 per minute")
async def auth_microsoft(request: Request):
    """Initiate OAuth flow with Microsoft Entra ID."""
    try:
        # Generate PKCE parameters
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        state = generate_state()
        
        # Store PKCE and state in session
        request.session['code_verifier'] = code_verifier
        request.session['oauth_state'] = state
        
        # Build authorization URL
        auth_params = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'scope': 'openid profile email',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'response_mode': 'query'
        }
        
        auth_url = f"{AUTHORIZATION_URL}?{urlencode(auth_params)}"
        
        logger.info(f"OAuth flow initiated - State: {state[:8]}...")
        return RedirectResponse(url=auth_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {e}")
        raise HTTPException(status_code=500, detail="Authentication setup failed")

@app.get("/auth/callback")
@limiter.limit("10 per minute")
async def auth_callback(request: Request):
    """Handle OAuth callback from Microsoft."""
    try:
        # Get parameters from callback
        code = request.query_params.get('code')
        state = request.query_params.get('state')
        error = request.query_params.get('error')
        
        # Check for errors
        if error:
            error_description = request.query_params.get('error_description', 'Unknown error')
            logger.error(f"OAuth error: {error} - {error_description}")
            return RedirectResponse(
                url=f"/login?error={error}&error_description={error_description}",
                status_code=302
            )
        
        # Validate state parameter (CSRF protection)
        session_state = request.session.get('oauth_state')
        if not state or state != session_state:
            logger.error("Invalid state parameter - possible CSRF attack")
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        # Get code verifier from session
        code_verifier = request.session.get('code_verifier')
        if not code_verifier:
            logger.error("Missing code verifier in session")
            raise HTTPException(status_code=400, detail="Missing code verifier")
        
        # Exchange authorization code for tokens
        token_data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'grant_type': 'authorization_code',
            'code_verifier': code_verifier
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        logger.info("Exchanging authorization code for tokens")
        response = requests.post(TOKEN_URL, data=token_data, headers=headers)
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
            raise HTTPException(status_code=400, detail="Token exchange failed")
        
        tokens = response.json()
        
        # Validate and decode ID token
        id_token = tokens.get('id_token')
        if not id_token:
            logger.error("No ID token received")
            raise HTTPException(status_code=400, detail="No ID token received")
        
        user_info = await validate_id_token(id_token)
        
        # Store user information in session
        user_data = {
            'sub': user_info.get('sub'),
            'name': user_info.get('name', user_info.get('preferred_username', 'Unknown')),
            'email': user_info.get('email', user_info.get('preferred_username')),
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token')
        }
        
        request.session['user'] = user_data
        request.session['login_time'] = datetime.utcnow().isoformat()
        
        # Clean up OAuth-specific session data
        request.session.pop('code_verifier', None)
        request.session.pop('oauth_state', None)
        
        logger.info(f"User authenticated successfully: {user_data['name']}")
        return RedirectResponse(url="/", status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in auth callback: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.get("/debug-info", response_class=HTMLResponse)
@limiter.limit("10 per minute")
async def debug_info(request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """Debug information page - requires authentication."""
    try:
        # Prepare debug information
        debug_data = {
            'user_info': {
                'name': user.get('name'),
                'email': user.get('email'),
                'sub': user.get('sub'),
                'has_access_token': bool(user.get('access_token')),
                'has_refresh_token': bool(user.get('refresh_token'))
            },
            'session_info': {
                'login_time': request.session.get('login_time'),
                'session_keys': list(request.session.keys())
            },
            'request_info': {
                'client_ip': get_remote_address(request),
                'user_agent': request.headers.get('user-agent'),
                'method': request.method,
                'url': str(request.url)
            },
            'security_headers': {
                'x_forwarded_proto': request.headers.get('x-forwarded-proto'),
                'x_forwarded_for': request.headers.get('x-forwarded-for'),
                'host': request.headers.get('host')
            }
        }
        
        logger.info(f"Debug info accessed by user: {user.get('name')}")
        
        return templates.TemplateResponse(
            "debug_info.html", 
            {"request": request, "user": user, "debug_data": debug_data}
        )
        
    except Exception as e:
        logger.error(f"Error generating debug info: {e}")
        raise HTTPException(status_code=500, detail="Error generating debug information")

@app.get("/logout")
@limiter.limit("10 per minute")
async def logout(request: Request):
    """Logout endpoint - clears session and redirects to Microsoft logout."""
    try:
        user = get_user_from_session(request)
        user_name = user.get('name', 'Unknown') if user else 'Anonymous'
        
        # Clear local session
        clear_session(request)
        
        # Build Microsoft logout URL
        #logout_params = {
            #'post_logout_redirect_uri': 'https://pretotype.com/logout-complete'
        #}
        #logout_url = f"{LOGOUT_URL}?{urlencode(logout_params)}"

        # Build Microsoft logout URL - MODIFIED FOR LOCALHOST
        logout_params = {
            'post_logout_redirect_uri': 'http://localhost:8080/logout-complete'  # Changed for localhost
        }
        logout_url = f"{LOGOUT_URL}?{urlencode(logout_params)}"
        
        logger.info(f"User logged out: {user_name}")
        return RedirectResponse(url=logout_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        # Even if there's an error, clear the session and redirect
        clear_session(request)
        return RedirectResponse(url="/logout-complete", status_code=302)

@app.get("/logout-complete", response_class=HTMLResponse)
@limiter.limit("10 per minute")
async def logout_complete(request: Request):
    """Logout completion page."""
    logger.info("Logout completed")
    return templates.TemplateResponse("logout.html", {"request": request})

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for load balancer."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Custom 404 handler."""
    logger.warning(f"404 error: {request.url}")
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "error_code": 404, "error_message": "Page not found"},
        status_code=404
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    """Custom 500 handler."""
    logger.error(f"500 error: {request.url}")
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "error_code": 500, "error_message": "Internal server error"},
        status_code=500
    )

if __name__ == "__main__":
    logger.info("Starting Secure OAuth Application")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8080)),
        log_level="info",
        access_log=True
    )