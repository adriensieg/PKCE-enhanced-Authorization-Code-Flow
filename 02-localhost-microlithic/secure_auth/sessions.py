"""Session management helper functions."""

import logging
from typing import Optional, Dict, Any
from fastapi import Request

logger = logging.getLogger(__name__)


def get_user_from_session(request: Request, state_store) -> Optional[Dict[str, Any]]:
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


def clear_session(request: Request, state_store):
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
