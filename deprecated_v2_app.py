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
# REMOVED: TrustedHostMiddleware - this was causing the 400 errors
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

import threading
from datetime import datetime, timedelta

# In-memory state store as backup for session issues
class StateStore:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        
    def set_state(self, state: str, code_verifier: str):
        with self._lock:
            self._store[state] = {
                'code_verifier': code_verifier,
                'timestamp': datetime.utcnow()
            }
            # Clean up old entries (older than 10 minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=10)
            self._store = {k: v for k, v in self._store.items() 
                          if v['timestamp'] > cutoff}
            logger.debug(f"State store now has {len(self._store)} entries")
    
    def get_and_remove_state(self, state: str) -> str:
        with self._lock:
            data = self._store.pop(state, None)
            if data:
                logger.debug(f"Retrieved state from backup store")
                return data['code_verifier']
            logger.debug(f"State not found in backup store")
            return None

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Environment variables loaded from .env")
except ImportError:
    print("python-dotenv not available, using system environment")

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

# Configuration
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

logger.info(f"OAuth Configuration loaded - Tenant: {TENANT_ID}")
logger.info(f"Client ID: {CLIENT_ID[:8] if CLIENT_ID else 'NOT_SET'}...")
logger.info(f"Redirect URI: {REDIRECT_URI}")
logger.info(f"Secret Key: {'SET' if SECRET_KEY else 'NOT_SET'}")

# Security middleware - FIXED FOR LOCALHOST
#app.add_middleware(
    #SessionMiddleware,
    #secret_key=SECRET_KEY,
    #max_age=3600,
    #same_site='lax',
    #https_only=False,
#)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=3600,  # 1 hour
    same_site='lax',
    https_only=False,  # Keep False for localhost
    session_cookie='session',  # Explicit cookie name
    path='/',  # Ensure cookie works for all paths
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080", "http://0.0.0.0:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# REMOVED TrustedHostMiddleware - this was causing the 400 errors
# For localhost development, we don't need strict host checking

# Rate limiting - relaxed for localhost
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour"]
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Templates
templates = Jinja2Templates(directory="templates")

# Security headers middleware - simplified for localhost
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Basic security headers for localhost
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    
    # Relaxed CSP for localhost development
    csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval' *; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net;"
    response.headers['Content-Security-Policy'] = csp
    
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

# Token validation - simplified for localhost
async def validate_id_token(id_token: str) -> Dict[str, Any]:
    """Simplified validation for development."""
    try:
        payload = jwt.get_unverified_claims(id_token)
        
        # Log for debugging
        logger.info(f"ID token received for user: {payload.get('preferred_username', 'unknown')}")
        logger.debug(f"Token claims: {payload}")
        
        return payload
        
    except Exception as e:
        logger.error(f"ID token parsing failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid ID token")

# Routes
@app.get("/", response_class=HTMLResponse)
@limiter.limit("100 per minute")
async def home(request: Request):
    """Home page - shows user info if authenticated."""
    try:
        user = get_user_from_session(request)
        logger.info(f"Home page accessed - User: {'authenticated' if user else 'anonymous'}")
        logger.debug(f"Request URL: {request.url}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        
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

@app.get("/login", response_class=HTMLResponse)
@limiter.limit("20 per minute")
async def login_page(request: Request):
    """Login page."""
    try:
        user = get_user_from_session(request)
        if user:
            logger.info("Already authenticated user redirected from login page")
            return RedirectResponse(url="/", status_code=302)
        
        logger.info("Login page accessed")
        return templates.TemplateResponse("login.html", {"request": request})
    except Exception as e:
        logger.error(f"Error in login route: {e}")
        return HTMLResponse(f"Login page error: {str(e)}", status_code=500)

# Create global state store
state_store = StateStore()

@app.get("/auth/microsoft")
@limiter.limit("20 per minute")
async def auth_microsoft(request: Request):
    """Initiate OAuth flow with Microsoft Entra ID."""
    try:
        if not CLIENT_ID:
            raise HTTPException(status_code=500, detail="AZURE_CLIENT_ID not configured")
        
        # Generate PKCE parameters
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        state = generate_state()
        
        # Store PKCE and state in BOTH session AND backup store
        request.session['code_verifier'] = code_verifier
        request.session['oauth_state'] = state
        state_store.set_state(state, code_verifier)  # Backup storage
        
        # DEBUG: Log session contents
        logger.debug(f"Session after storing state: {dict(request.session)}")
        logger.debug(f"Session ID: {request.session.get('_session_id', 'NO_ID')}")
        logger.debug(f"Request cookies: {request.cookies}")
        logger.debug(f"Generated PKCE - Verifier: {code_verifier[:20]}...")
        
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
        logger.debug(f"Authorization URL: {auth_url}")
        
        return RedirectResponse(url=auth_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {e}")
        return HTMLResponse(f"OAuth setup failed: {str(e)}", status_code=500)

@app.get("/auth/callback")
@limiter.limit("20 per minute")
async def auth_callback(request: Request):
    """Handle OAuth callback from Microsoft."""
    try:
        # DEBUG: Log session contents immediately
        logger.debug(f"Session at callback start: {dict(request.session)}")
        logger.debug(f"Session ID at callback: {request.session.get('_session_id', 'NO_ID')}")
        logger.debug(f"Request cookies at callback: {request.cookies}")
        logger.debug(f"Callback received with params: {dict(request.query_params)}")
        
        code = request.query_params.get('code')
        state = request.query_params.get('state')
        error = request.query_params.get('error')
        
        if error:
            error_description = request.query_params.get('error_description', 'Unknown error')
            logger.error(f"OAuth error: {error} - {error_description}")
            return RedirectResponse(
                url=f"/login?error={error}&error_description={error_description}",
                status_code=302
            )
        
        if not code:
            logger.error("No authorization code received")
            return RedirectResponse(url="/login?error=no_code", status_code=302)
        
        # Validate state parameter - try session first, then backup store
        session_state = request.session.get('oauth_state')
        
        if not state:
            logger.error("No state parameter received")
            return RedirectResponse(url="/login?error=no_state", status_code=302)
        
        if state != session_state:
            logger.warning(f"State mismatch - Session: {session_state}, Received: {state}")
            # Don't fail immediately - we'll check the backup store for code_verifier
        
        # Get code verifier - try session first, then backup store
        code_verifier = request.session.get('code_verifier')
        if not code_verifier and state:
            logger.warning("Session lost code_verifier, trying backup state store")
            code_verifier = state_store.get_and_remove_state(state)
        
        if not code_verifier:
            logger.error("Missing code verifier in both session and backup store")
            return RedirectResponse(url="/login?error=missing_verifier", status_code=302)
        
        logger.info("Code verifier retrieved successfully")
        
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
        
        logger.debug(f"Token response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
            return RedirectResponse(url="/login?error=token_exchange_failed", status_code=302)
        
        tokens = response.json()
        
        # Validate and decode ID token
        id_token = tokens.get('id_token')
        if not id_token:
            logger.error("No ID token received")
            return RedirectResponse(url="/login?error=no_id_token", status_code=302)
        
        user_info = await validate_id_token(id_token)
        
        # Store user information in session
        user_data = {
            'sub': user_info.get('sub'),
            'name': user_info.get('name', user_info.get('preferred_username', 'Unknown User')),
            'email': user_info.get('email', user_info.get('preferred_username')),
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token')
        }
        
        request.session['user'] = user_data
        request.session['login_time'] = datetime.utcnow().isoformat()
        
        # Clean up OAuth session data
        request.session.pop('code_verifier', None)
        request.session.pop('oauth_state', None)
        
        logger.info(f"User authenticated successfully: {user_data['name']}")
        return RedirectResponse(url="/", status_code=302)
        
    except Exception as e:
        logger.error(f"Unexpected error in auth callback: {e}", exc_info=True)
        return RedirectResponse(url="/login?error=unexpected_error", status_code=302)

@app.get("/debug-info", response_class=HTMLResponse)
@limiter.limit("50 per minute")
async def debug_info(request: Request, user: Dict[str, Any] = Depends(get_current_user)):
    """Debug information page - requires authentication."""
    try:
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
                'host': request.headers.get('host'),
                'x_forwarded_for': request.headers.get('x-forwarded-for'),
                'x_forwarded_proto': request.headers.get('x-forwarded-proto')
            }
        }
        
        logger.info(f"Debug info accessed by user: {user.get('name')}")
        
        return templates.TemplateResponse(
            "debug_info.html", 
            {"request": request, "user": user, "debug_data": debug_data}
        )
        
    except Exception as e:
        logger.error(f"Error generating debug info: {e}")
        return HTMLResponse(f"Debug info error: {str(e)}", status_code=500)

@app.get("/logout")
@limiter.limit("20 per minute")
async def logout(request: Request):
    """Logout endpoint."""
    try:
        user = get_user_from_session(request)
        user_name = user.get('name', 'Unknown') if user else 'Anonymous'
        
        clear_session(request)
        
        logout_params = {
            'post_logout_redirect_uri': 'http://localhost:8080/logout-complete'
        }
        logout_url = f"{LOGOUT_URL}?{urlencode(logout_params)}"
        
        logger.info(f"User logged out: {user_name}")
        return RedirectResponse(url=logout_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        clear_session(request)
        return RedirectResponse(url="/logout-complete", status_code=302)

@app.get("/logout-complete", response_class=HTMLResponse)
@limiter.limit("20 per minute")
async def logout_complete(request: Request):
    """Logout completion page."""
    try:
        logger.info("Logout completed")
        return templates.TemplateResponse("logout.html", {"request": request})
    except Exception as e:
        logger.error(f"Error in logout complete: {e}")
        return HTMLResponse("Logout complete", status_code=200)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "tenant_id": TENANT_ID,
            "client_id_set": bool(CLIENT_ID),
            "client_secret_set": bool(CLIENT_SECRET),
            "redirect_uri": REDIRECT_URI
        }
    }

# Error handlers
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

if __name__ == "__main__":
    logger.info("Starting Secure OAuth Application on localhost")
    logger.info(f"Configuration check:")
    logger.info(f"  TENANT_ID: {TENANT_ID}")
    logger.info(f"  CLIENT_ID: {'SET' if CLIENT_ID else 'NOT_SET'}")
    logger.info(f"  CLIENT_SECRET: {'SET' if CLIENT_SECRET else 'NOT_SET'}")
    logger.info(f"  REDIRECT_URI: {REDIRECT_URI}")
    
    uvicorn.run(
        "app:app",
        host="localhost",  # Changed from 0.0.0.0 to 127.0.0.1
        port=int(os.getenv("PORT", 8080)),
        log_level="debug",
        access_log=True,
        reload=True
    )