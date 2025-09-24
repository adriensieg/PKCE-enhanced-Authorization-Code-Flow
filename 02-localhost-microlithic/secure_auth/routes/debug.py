"""Debug and session testing routes."""

import logging
from datetime import datetime
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi.util import get_remote_address
from ..dependencies import get_current_user
from ..sessions import get_user_from_session
from typing import Dict, Any

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["debug"])


@router.get("/debug-info", response_class=HTMLResponse)
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
        
        templates = request.app.state.templates
        return templates.TemplateResponse(
            "debug_info.html", 
            {"request": request, "user": user, "debug_data": debug_data}
        )
        
    except Exception as e:
        logger.error(f"Error generating debug info: {e}")
        return HTMLResponse(f"Debug info error: {str(e)}", status_code=500)


@router.get("/session-debug")
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


@router.get("/session-check")
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


@router.get("/session-test")
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


@router.get("/session-persist-test")
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


@router.get("/session-persist-check")
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


@router.get("/health")
async def health_check(request: Request):
    """Health check endpoint with enhanced configuration info."""
    settings = request.app.state.settings
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "tenant_id": settings.TENANT_ID,
            "client_id_set": bool(settings.CLIENT_ID),
            "client_secret_set": bool(settings.CLIENT_SECRET),
            "redirect_uri": settings.REDIRECT_URI,
            "jwks_url": settings.JWKS_URL
        },
        "session_config": {
            "cookie_name": "oauth_session",
            "max_age": 3600,
            "same_site": "lax",
            "https_only": False,
            "path": "/"
        }
    }
