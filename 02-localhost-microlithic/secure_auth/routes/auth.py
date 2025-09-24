"""OAuth authentication routes."""

import json
import secrets
import logging
import requests
from datetime import datetime
from urllib.parse import urlencode
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from ..crypto import generate_code_verifier, generate_code_challenge, generate_state, generate_nonce
from ..sessions import get_user_from_session, clear_session
from ..validators import validate_id_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["authentication"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    try:
        state_store = request.app.state.state_store
        user = get_user_from_session(request, state_store)
        if user:
            logger.info("Already authenticated user redirected from login page")
            return RedirectResponse(url="/", status_code=302)
        
        logger.info("Login page accessed")
        templates = request.app.state.templates
        return templates.TemplateResponse("login.html", {"request": request})
    except Exception as e:
        logger.error(f"Error in login route: {e}")
        return HTMLResponse(f"Login page error: {str(e)}", status_code=500)


@router.get("/auth/microsoft")
async def auth_microsoft(request: Request):
    """Initiate OAuth flow with Microsoft Entra ID."""
    try:
        settings = request.app.state.settings
        state_store = request.app.state.state_store
        
        if not settings.CLIENT_ID:
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
            'client_id': settings.CLIENT_ID,
            'response_type': 'code',
            'redirect_uri': settings.REDIRECT_URI,
            'scope': 'openid profile email offline_access',
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'response_mode': 'query'
        }
        
        auth_url = f"{settings.AUTHORIZATION_URL}?{urlencode(auth_params)}"
        
        logger.info(f"OAuth flow initiated - State: {state[:8]}..., Nonce: {nonce[:8]}...")
        
        return RedirectResponse(url=auth_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {e}")
        return HTMLResponse(f"OAuth setup failed: {str(e)}", status_code=500)


@router.get("/auth/callback")
async def auth_callback(request: Request):
    """Handle OAuth callback from Microsoft with enhanced session debugging."""
    try:
        settings = request.app.state.settings
        state_store = request.app.state.state_store
        jwks_cache = request.app.state.jwks_cache
        
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
            'client_id': settings.CLIENT_ID,
            'client_secret': settings.CLIENT_SECRET,
            'code': code,
            'redirect_uri': settings.REDIRECT_URI,
            'grant_type': 'authorization_code',
            'code_verifier': code_verifier
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        logger.info("Exchanging authorization code for tokens")
        response = requests.post(settings.TOKEN_URL, data=token_data, headers=headers)
        
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
        
        user_info = await validate_id_token(
            id_token, 
            expected_nonce,
            jwks_cache,
            settings.JWKS_URL,
            settings.CLIENT_ID,
            settings.TENANT_ID
        )
        
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


@router.get("/auth/complete")
async def auth_complete(request: Request):
    """Complete authentication by retrieving user data and creating persistent session."""
    try:
        state_store = request.app.state.state_store
        
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


@router.get("/logout")
async def logout(request: Request):
    """Logout endpoint with persistent session cleanup."""
    try:
        settings = request.app.state.settings
        state_store = request.app.state.state_store
        
        user = get_user_from_session(request, state_store)
        user_name = user.get('name', 'Unknown') if user else 'Anonymous'
        
        # Clear both browser and persistent sessions
        clear_session(request, state_store)
        
        logout_params = {
            'post_logout_redirect_uri': 'http://localhost:8080/logout-complete'
        }
        logout_url = f"{settings.LOGOUT_URL}?{urlencode(logout_params)}"
        
        logger.info(f"User logged out: {user_name}")
        return RedirectResponse(url=logout_url, status_code=302)
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        state_store = request.app.state.state_store
        clear_session(request, state_store)
        return RedirectResponse(url="/logout-complete", status_code=302)


@router.get("/logout-complete", response_class=HTMLResponse)
async def logout_complete(request: Request):
    """Logout completion page."""
    try:
        logger.info("Logout completed")
        templates = request.app.state.templates
        return templates.TemplateResponse("logout.html", {"request": request})
    except Exception as e:
        logger.error(f"Error in logout complete: {e}")
        return HTMLResponse("Logout complete", status_code=200)
