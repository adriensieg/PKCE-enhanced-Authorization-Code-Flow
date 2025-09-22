import os
import logging
import secrets
import base64
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from urllib.parse import urlencode, parse_qs
import time

import requests
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.requests import Request as StarletteRequest
from jose import JWTError, jwt, jwk
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import uvicorn

import threading
from datetime import datetime, timedelta

# Enhanced state store that acts as a session replacement
class StateStore:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        
    def set_state(self, state: str, code_verifier: str, nonce: str):
        """Store OAuth state data."""
        with self._lock:
            self._store[state] = {
                'code_verifier': code_verifier,
                'nonce': nonce,
                'timestamp': datetime.utcnow(),
                'type': 'oauth'
            }
            self._cleanup()
            logger.debug(f"OAuth state stored - Store has {len(self._store)} entries")
    
    def get_and_remove_state(self, state: str) -> tuple[str, str]:
        """Retrieve and remove OAuth state data."""
        with self._lock:
            data = self._store.pop(state, None)
            if data and data.get('type') == 'oauth':
                logger.debug(f"Retrieved OAuth state from store")
                return data['code_verifier'], data['nonce']
            logger.debug(f"OAuth state not found in store")
            return None, None
    
    def store_temp_data(self, key: str, data: str, metadata: str = None):
        """Store temporary data (like user info during auth flow)."""
        with self._lock:
            self._store[key] = {
                'data': data,
                'metadata': metadata,
                'timestamp': datetime.utcnow(),
                'type': 'temp'
            }
            self._cleanup()
            logger.debug(f"Temp data stored with key: {key}")
    
    def get_and_remove_temp_data(self, key: str) -> tuple[str, str]:
        """Retrieve and remove temporary data."""
        with self._lock:
            data = self._store.pop(key, None)
            if data and data.get('type') == 'temp':
                logger.debug(f"Retrieved temp data from store")
                return data.get('data'), data.get('metadata')
            logger.debug(f"Temp data not found in store")
            return None, None
    
    def store_user_session(self, session_id: str, user_data: dict):
        """Store user session data permanently (until explicit logout)."""
        with self._lock:
            self._store[f"session_{session_id}"] = {
                'user_data': user_data,
                'timestamp': datetime.utcnow(),
                'login_time': datetime.utcnow().isoformat(),
                'type': 'user_session'
            }
            self._cleanup()
            logger.debug(f"User session stored with ID: {session_id}")
    
    def get_user_session(self, session_id: str) -> dict:
        """Retrieve user session data (without removing it)."""
        with self._lock:
            data = self._store.get(f"session_{session_id}")
            if data and data.get('type') == 'user_session':
                # Check if session is still valid (24 hours)
                if datetime.utcnow() - data['timestamp'] < timedelta(hours=24):
                    logger.debug(f"Retrieved valid user session: {session_id}")
                    return data.get('user_data', {})
                else:
                    # Expired session
                    logger.debug(f"Session expired: {session_id}")
                    self._store.pop(f"session_{session_id}", None)
            return {}
    
    def remove_user_session(self, session_id: str):
        """Remove user session (logout)."""
        with self._lock:
            removed = self._store.pop(f"session_{session_id}", None)
            if removed:
                logger.debug(f"User session removed: {session_id}")
                return True
            return False
    
    def _cleanup(self):
        """Clean up old entries."""
        cutoff = datetime.utcnow() - timedelta(hours=2)  # 2 hour cleanup for temp data
        session_cutoff = datetime.utcnow() - timedelta(hours=24)  # 24 hour cleanup for sessions
        
        to_remove = []
        for key, value in self._store.items():
            if value.get('type') in ['oauth', 'temp'] and value['timestamp'] < cutoff:
                to_remove.append(key)
            elif value.get('type') == 'user_session' and value['timestamp'] < session_cutoff:
                to_remove.append(key)
        
        for key in to_remove:
            self._store.pop(key, None)

# JWKS cache
class JWKSCache:
    def __init__(self):
        self._cache = {}
        self._last_fetch = {}
        self._lock = threading.Lock()
        self.cache_duration = timedelta(hours=1)  # Cache for 1 hour
    
    def get_jwks(self, jwks_url: str) -> dict:
        with self._lock:
            now = datetime.utcnow()
            
            # Check if we have cached data that's still valid
            if (jwks_url in self._cache and 
                jwks_url in self._last_fetch and 
                now - self._last_fetch[jwks_url] < self.cache_duration):
                return self._cache[jwks_url]
            
            # Fetch fresh JWKS
            try:
                response = requests.get(jwks_url, timeout=10)
                response.raise_for_status()
                jwks = response.json()
                
                self._cache[jwks_url] = jwks
                self._last_fetch[jwks_url] = now
                
                logger.info(f"JWKS fetched and cached for {jwks_url}")
                return jwks
                
            except Exception as e:
                logger.error(f"Failed to fetch JWKS from {jwks_url}: {e}")
                # Return cached version if available, even if expired
                return self._cache.get(jwks_url, {})

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
TENANT_ID=''
CLIENT_ID=''
CLIENT_SECRET=''
REDIRECT_URI='http://localhost:8080/auth/callback'
SECRET_KEY=''

# Microsoft Entra ID endpoints
AUTHORIZATION_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize'
TOKEN_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token'
JWKS_URL = f'https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys'
LOGOUT_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/logout'

logger.info(f"OAuth Configuration loaded - Tenant: {TENANT_ID}")
logger.info(f"Client ID: {CLIENT_ID[:8] if CLIENT_ID else 'NOT_SET'}...")
logger.info(f"Redirect URI: {REDIRECT_URI}")
logger.info(f"Secret Key: {'SET' if SECRET_KEY else 'NOT_SET'}")

# Initialize global objects
state_store = StateStore()
jwks_cache = JWKSCache()

# CRITICAL: Add middlewares in correct order (they execute in reverse order)
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
    secret_key=SECRET_KEY,
    max_age=3600,  # 1 hour
    same_site='lax',  # Important for OAuth redirects
    https_only=True,  # False for localhost development
    session_cookie='oauth_session',  # Explicit cookie name to avoid conflicts
    path='/'  # Ensure cookie is available for all paths
)

# Templates
templates = Jinja2Templates(directory="templates")

# Enhanced security headers middleware with session debugging
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

def generate_nonce() -> str:
    """Generate a secure nonce for ID token validation."""
    return secrets.token_urlsafe(32)

# Enhanced session helper functions that use persistent storage
def get_user_from_session(request: Request) -> Optional[Dict[str, Any]]:
    """Get user information from persistent session store."""
    try:
        # Check if session exists
        if not hasattr(request, 'session') or not request.session:
            logger.debug("No browser session available")
            return None
        
        # Get persistent session ID from browser session
        persistent_session_id = request.session.get('persistent_session_id')
        if not persistent_session_id:
            logger.debug("No persistent session ID in browser session")
            logger.debug(f"Browser session contents: {dict(request.session)}")
            return None
        
        # Retrieve user data from persistent store
        user_data = state_store.get_user_session(persistent_session_id)
        if not user_data:
            logger.debug(f"No user data found for session ID: {persistent_session_id}")
            # Clean up invalid session reference
            request.session.pop('persistent_session_id', None)
            request.session.pop('authenticated', None)
            return None
        
        logger.debug(f"User found in persistent store: {user_data.get('name', 'Unknown')}")
        return user_data
        
    except Exception as e:
        logger.error(f"Error getting user from persistent session: {e}")
        return None

def clear_session(request: Request):
    """Clear both browser session and persistent session data."""
    try:
        # Get persistent session ID before clearing
        persistent_session_id = request.session.get('persistent_session_id')
        
        # Clear browser session
        request.session.clear()
        
        # Remove from persistent store
        if persistent_session_id:
            state_store.remove_user_session(persistent_session_id)
            logger.info(f"Persistent session cleared: {persistent_session_id}")
        
        logger.info("Session cleared completely")
        
    except Exception as e:
        logger.error(f"Error clearing session: {e}")
        # Force clear browser session even if persistent store fails
        try:
            request.session.clear()
        except:
            pass

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

# Enhanced token validation using python-jose with proper key handling
async def validate_id_token(id_token: str, expected_nonce: str) -> Dict[str, Any]:
    """Validate ID token with proper JWT verification using python-jose."""
    try:
        # Get the header to find the key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get('kid')
        
        if not kid:
            raise ValueError("No key ID in token header")
        
        # Get JWKS
        jwks_data = jwks_cache.get_jwks(JWKS_URL)
        
        # Find the correct key
        signing_key = None
        for key in jwks_data.get('keys', []):
            if key.get('kid') == kid:
                signing_key = key
                break
        
        if not signing_key:
            raise ValueError(f"Signing key not found for kid: {kid}")
        
        # Create a proper JWK for python-jose
        jose_key = signing_key.copy()
        if 'alg' not in jose_key:
            jose_key['alg'] = 'RS256'
        
        logger.debug(f"Using JWK with kid: {kid}")
        
        # Try to construct the key using jose
        try:
            public_key = jwk.construct(jose_key)
            logger.debug("Successfully constructed JWK using jose")
        except Exception as jwk_error:
            logger.error(f"Jose JWK construction failed: {jwk_error}")
            # Fallback: use certificate from x5c if available
            if 'x5c' in signing_key and signing_key['x5c']:
                cert_str = signing_key['x5c'][0]
                cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_str}\n-----END CERTIFICATE-----"
                public_key = cert_pem
                logger.debug("Using x5c certificate as fallback")
            else:
                raise ValueError(f"Could not construct key and no x5c certificate available: {jwk_error}")
        
        # First, let's see what the actual issuer is
        unverified_payload = jwt.get_unverified_claims(id_token)
        actual_issuer = unverified_payload.get('iss')
        logger.debug(f"Token issuer: {actual_issuer}")
        
        # Microsoft can use different issuer formats
        expected_issuers = [
            f"https://sts.windows.net/{TENANT_ID}/",
            f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
        ]
        
        # Try with the actual issuer first
        issuer_to_use = actual_issuer if actual_issuer in expected_issuers else expected_issuers[0]
        
        # Verify and decode the token
        try:
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=['RS256'],
                audience=CLIENT_ID,
                issuer=issuer_to_use,
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                }
            )
        except Exception as decode_error:
            logger.error(f"JWT decode failed with constructed key: {decode_error}")
            # Final fallback: try with x5c certificate directly
            if 'x5c' in signing_key and signing_key['x5c']:
                cert_str = signing_key['x5c'][0]
                cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_str}\n-----END CERTIFICATE-----"
                payload = jwt.decode(
                    id_token,
                    cert_pem,
                    algorithms=['RS256'],
                    audience=CLIENT_ID,
                    issuer=issuer_to_use,
                    options={
                        "verify_signature": True,
                        "verify_aud": True,
                        "verify_iss": True,
                        "verify_exp": True,
                        "verify_nbf": True,
                    }
                )
                logger.debug("Successfully decoded JWT using x5c certificate")
            else:
                raise decode_error
        
        # Validate nonce
        token_nonce = payload.get('nonce')
        if not token_nonce or token_nonce != expected_nonce:
            raise ValueError(f"Nonce validation failed. Expected: {expected_nonce}, Got: {token_nonce}")
        
        # Additional validations
        now = int(time.time())
        
        # Check expiration
        exp = payload.get('exp')
        if not exp or exp < now:
            raise ValueError("Token has expired")
        
        # Check not before
        nbf = payload.get('nbf')
        if nbf and nbf > now + 60:
            raise ValueError("Token not yet valid")
        
        # Check issued at
        iat = payload.get('iat')
        if iat and iat > now + 60:
            raise ValueError("Token issued in the future")
        
        logger.info(f"ID token validated successfully for user: {payload.get('preferred_username', 'unknown')}")
        return payload
        
    except JWTError as e:
        logger.error(f"JWT validation failed: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {str(e)}")
    except Exception as e:
        logger.error(f"ID token validation failed: {e}")
        raise HTTPException(status_code=400, detail=f"Token validation error: {str(e)}")

# Routes
@app.get("/", response_class=HTMLResponse)
@limiter.limit("100 per minute")
async def home(request: Request):
    """Home page - shows user info if authenticated."""
    try:
        # Enhanced session debugging
        logger.debug(f"Home page - Session available: {hasattr(request, 'session')}")
        logger.debug(f"Home page - Session keys: {list(request.session.keys()) if hasattr(request, 'session') else 'No session'}")
        logger.debug(f"Home page - Session data: {dict(request.session) if hasattr(request, 'session') else 'No session'}")
        
        user = get_user_from_session(request)
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
        nonce = generate_nonce()
        
        # CRITICAL: Clear any existing session data first to avoid conflicts
        request.session.clear()
        
        # Store PKCE, state, and nonce in BOTH session AND backup store
        request.session['code_verifier'] = code_verifier
        request.session['oauth_state'] = state
        request.session['nonce'] = nonce
        state_store.set_state(state, code_verifier, nonce)  # Backup storage
        
        logger.debug(f"OAuth flow initiated - Stored in session: {list(request.session.keys())}")
        logger.debug(f"Generated OAuth parameters - State: {state[:8]}..., Nonce: {nonce[:8]}...")
        
        # Build authorization URL with offline_access scope for refresh token
        auth_params = {
            'client_id': CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI,
            'scope': 'openid profile email offline_access',
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'response_mode': 'query'
        }
        
        auth_url = f"{AUTHORIZATION_URL}?{urlencode(auth_params)}"
        
        logger.info(f"OAuth flow initiated - State: {state[:8]}..., Nonce: {nonce[:8]}...")
        
        return RedirectResponse(url=auth_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {e}")
        return HTMLResponse(f"OAuth setup failed: {str(e)}", status_code=500)

@app.get("/auth/callback")
@limiter.limit("20 per minute")
async def auth_callback(request: Request):
    """Handle OAuth callback from Microsoft with enhanced session debugging."""
    try:
        logger.debug(f"Callback received with params: {dict(request.query_params)}")
        logger.debug(f"Callback session before processing: {dict(request.session)}")
        
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
        
        # Validate state parameter
        session_state = request.session.get('oauth_state')
        
        if not state:
            logger.error("No state parameter received")
            return RedirectResponse(url="/login?error=no_state", status_code=302)
        
        if state != session_state:
            logger.warning(f"State mismatch - Session: {session_state}, Received: {state}")
        
        # Get code verifier and nonce - try session first, then backup store
        code_verifier = request.session.get('code_verifier')
        expected_nonce = request.session.get('nonce')
        
        if not code_verifier or not expected_nonce:
            if state:
                logger.warning("Session lost data, trying backup state store")
                code_verifier, expected_nonce = state_store.get_and_remove_state(state)
        
        if not code_verifier or not expected_nonce:
            logger.error("Missing code verifier or nonce in both session and backup store")
            return RedirectResponse(url="/login?error=missing_oauth_data", status_code=302)
        
        logger.info("Code verifier and nonce retrieved successfully")
        
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
            return RedirectResponse(url="/login?error=token_exchange_failed", status_code=302)
        
        tokens = response.json()
        logger.debug(f"Token response keys: {list(tokens.keys())}")
        
        # Validate and decode ID token with nonce verification
        id_token = tokens.get('id_token')
        if not id_token:
            logger.error("No ID token received")
            return RedirectResponse(url="/login?error=no_id_token", status_code=302)
        
        user_info = await validate_id_token(id_token, expected_nonce)
        
        # CRITICAL SESSION HANDLING: Force complete session regeneration
        logger.debug("Starting session replacement process...")
        logger.debug(f"Session before clearing: {dict(request.session)}")
        
        # Step 1: Store user data
        user_data = {
            'sub': user_info.get('sub'),
            'name': user_info.get('name', user_info.get('preferred_username', 'Unknown User')),
            'email': user_info.get('email', user_info.get('preferred_username')),
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token')
        }
        
        # Step 2: RADICAL approach - create entirely new session by clearing and using different approach
        # Store the user data in our backup store temporarily
        temp_session_id = secrets.token_urlsafe(32)
        state_store.store_temp_data(f"user_{temp_session_id}", 
                                  json.dumps(user_data), 
                                  datetime.utcnow().isoformat())
        
        # Step 3: Clear session completely
        request.session.clear()
        
        # Step 4: Store minimal redirect info that points to our backup
        request.session['temp_user_id'] = temp_session_id
        request.session['auth_complete'] = True
        
        # Step 5: Force session save
        if hasattr(request.session, 'save'):
            request.session.save()
            logger.debug("Session manually saved with temp data")
        
        logger.debug(f"Temporary session created with ID: {temp_session_id}")
        logger.info(f"User authenticated successfully: {user_data['name']}")
        
        # Step 6: Redirect to a completion handler instead of home
        redirect_response = RedirectResponse(url="/auth/complete", status_code=302)
        redirect_response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        redirect_response.headers['Pragma'] = 'no-cache'
        redirect_response.headers['Expires'] = '0'
        
        return redirect_response
        
    except Exception as e:
        logger.error(f"Unexpected error in auth callback: {e}", exc_info=True)
        return RedirectResponse(url="/login?error=unexpected_error", status_code=302)

@app.get("/auth/complete")
@limiter.limit("20 per minute")
async def auth_complete(request: Request):
    """Complete authentication by retrieving user data and creating persistent session."""
    try:
        logger.debug(f"Auth complete - Session: {dict(request.session)}")
        
        temp_user_id = request.session.get('temp_user_id')
        auth_complete = request.session.get('auth_complete')
        
        if not temp_user_id or not auth_complete:
            logger.error("No temporary user ID or auth complete flag")
            return RedirectResponse(url="/login?error=auth_incomplete", status_code=302)
        
        # Retrieve user data from backup store
        user_data_json, timestamp_str = state_store.get_and_remove_temp_data(f"user_{temp_user_id}")
        
        if not user_data_json:
            logger.error("Could not retrieve user data from backup store")
            return RedirectResponse(url="/login?error=user_data_lost", status_code=302)
        
        try:
            user_data = json.loads(user_data_json)
        except json.JSONDecodeError as e:
            logger.error(f"Could not decode user data: {e}")
            return RedirectResponse(url="/login?error=user_data_corrupt", status_code=302)
        
        # Generate a persistent session ID
        persistent_session_id = secrets.token_urlsafe(32)
        
        # Store user data in our persistent store
        state_store.store_user_session(persistent_session_id, user_data)
        
        # Clear browser session and store only the persistent session ID
        request.session.clear()
        request.session['persistent_session_id'] = persistent_session_id
        request.session['authenticated'] = True
        
        if hasattr(request.session, 'save'):
            request.session.save()
        
        logger.debug(f"Browser session after auth complete: {dict(request.session)}")
        logger.info(f"Authentication completed for user: {user_data['name']}")
        logger.info(f"Persistent session created: {persistent_session_id}")
        
        # Success page with auto-redirect
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Complete</title>
            <meta http-equiv="refresh" content="2;url=/">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .success {{ color: green; }}
                .loading {{ margin: 20px; }}
            </style>
        </head>
        <body>
            <h1 class="success">✅ Authentication Successful!</h1>
            <p>Welcome, <strong>{user_data['name']}</strong>!</p>
            <p>You will be redirected to the home page in 2 seconds...</p>
            <div class="loading">
                <p><a href="/">Click here if you are not redirected automatically</a></p>
            </div>
            <script>
                console.log('Authentication complete - Session ID: {persistent_session_id[:8]}...');
                setTimeout(function() {{
                    window.location.href = '/';
                }}, 2000);
            </script>
        </body>
        </html>
        """, status_code=200)
        
    except Exception as e:
        logger.error(f"Error in auth complete: {e}", exc_info=True)
        return RedirectResponse(url="/login?error=auth_complete_failed", status_code=302)

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
                'has_refresh_token': bool(user.get('refresh_token')),
                'access_token_preview': user.get('access_token', '')[:50] + '...' if user.get('access_token') else 'None',
                'refresh_token_preview': user.get('refresh_token', '')[:50] + '...' if user.get('refresh_token') else 'None'
            },
            'session_info': {
                'login_time': request.session.get('login_time'),
                'session_keys': list(request.session.keys()),
                'authenticated_flag': request.session.get('authenticated'),
                'full_session': dict(request.session)
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
                'x_forwarded_proto': request.headers.get('x-forwarded-proto'),
                'cookie_header': request.headers.get('cookie', 'No cookies')[:200] + '...' if request.headers.get('cookie') else 'No cookies'
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
    """Logout endpoint with persistent session cleanup."""
    try:
        user = get_user_from_session(request)
        user_name = user.get('name', 'Unknown') if user else 'Anonymous'
        
        # Clear both browser and persistent sessions
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

@app.get("/session-debug")
async def session_debug(request: Request):
    """Debug session storage step by step with enhanced logging."""
    
    # Step 1: Log current session state
    logger.debug(f"Session debug - Initial state: {dict(request.session)}")
    
    # Step 2: Clear any existing session
    request.session.clear()
    logger.debug(f"Session debug - After clear: {dict(request.session)}")
    
    # Step 3: Store test data
    request.session['test_user'] = 'John Doe'
    request.session['test_time'] = datetime.utcnow().isoformat()
    request.session['test_flag'] = True
    
    # Step 4: Force session save if available
    if hasattr(request.session, 'save'):
        request.session.save()
        logger.debug("Session manually saved")
    
    # Step 5: Check immediate storage
    immediate_keys = list(request.session.keys())
    immediate_user = request.session.get('test_user')
    
    logger.debug(f"Session debug - After storage: {dict(request.session)}")
    
    return {
        "step": "session_debug",
        "immediate_keys": immediate_keys,
        "immediate_user": immediate_user,
        "session_data": dict(request.session),
        "session_id_exists": hasattr(request, 'session'),
        "middleware_info": "SessionMiddleware configured with oauth_session cookie"
    }

@app.get("/session-check")
async def session_check(request: Request):
    """Check what's in session after a redirect with full debugging."""
    
    session_data = dict(request.session) if hasattr(request, 'session') else {}
    logger.debug(f"Session check - Current session: {session_data}")
    
    return {
        "step": "session_check", 
        "keys": list(request.session.keys()) if hasattr(request, 'session') else [],
        "test_user": request.session.get('test_user') if hasattr(request, 'session') else None,
        "all_data": session_data,
        "has_session": hasattr(request, 'session'),
        "cookie_header": request.headers.get('cookie', 'No cookie header'),
        "user_agent": request.headers.get('user-agent', 'No user agent')
    }

@app.get("/session-test")
async def session_test(request: Request):
    """Test session storage and retrieval with comprehensive debugging."""
    
    # Clear and test
    request.session.clear()
    
    # Store a test value
    request.session['test'] = 'session_working'
    request.session['timestamp'] = datetime.utcnow().isoformat()
    
    # Force save if available
    if hasattr(request.session, 'save'):
        request.session.save()
    
    # Retrieve it
    test_value = request.session.get('test')
    
    # Get all session data
    session_data = dict(request.session)
    
    logger.debug(f"Session test - Data stored: {session_data}")
    
    return {
        "test_stored": test_value,
        "all_session_data": session_data,
        "session_keys": list(request.session.keys()),
        "cookie_name": "oauth_session",
        "session_exists": hasattr(request, 'session'),
        "test_result": "PASS" if test_value == 'session_working' else "FAIL"
    }

@app.get("/session-persist-test")
async def session_persist_test(request: Request):
    """Test session persistence across redirects."""
    
    # Store test data
    request.session['persist_test'] = 'redirect_test_data'
    request.session['persist_time'] = datetime.utcnow().isoformat()
    
    # Force save
    if hasattr(request.session, 'save'):
        request.session.save()
    
    logger.debug(f"Persist test - Stored data, redirecting: {dict(request.session)}")
    
    # Redirect to check endpoint
    return RedirectResponse(url="/session-persist-check", status_code=302)

@app.get("/session-persist-check")
async def session_persist_check(request: Request):
    """Check if session data persisted across redirect."""
    
    session_data = dict(request.session)
    persist_test = request.session.get('persist_test')
    persist_time = request.session.get('persist_time')
    
    logger.debug(f"Persist check - Session after redirect: {session_data}")
    
    result = {
        "persist_test_value": persist_test,
        "persist_time": persist_time,
        "full_session": session_data,
        "test_result": "PASS" if persist_test == 'redirect_test_data' else "FAIL",
        "cookie_header": request.headers.get('cookie', 'No cookies'),
        "session_keys": list(request.session.keys())
    }
    
    return result

@app.get("/health")
async def health_check():
    """Health check endpoint with enhanced configuration info."""
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "tenant_id": TENANT_ID,
            "client_id_set": bool(CLIENT_ID),
            "client_secret_set": bool(CLIENT_SECRET),
            "redirect_uri": REDIRECT_URI,
            "jwks_url": JWKS_URL
        },
        "session_config": {
            "cookie_name": "oauth_session",
            "max_age": 3600,
            "same_site": "lax",
            "https_only": False,
            "path": "/"
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
    logger.info(f"  Session Cookie: oauth_session")
    
    uvicorn.run(
        "app:app",
        host="localhost",
        port=int(os.getenv("PORT", 8080)),
        log_level="debug",
        access_log=True,
        reload=True
    )
