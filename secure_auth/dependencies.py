"""FastAPI dependencies for authentication."""

import logging
from typing import Dict, Any
from fastapi import Request, HTTPException, status
from .sessions import get_user_from_session

logger = logging.getLogger(__name__)


async def get_current_user(request: Request) -> Dict[str, Any]:
    """FastAPI dependency to get current authenticated user."""
    # Get state_store from app state
    state_store = request.app.state.state_store
    
    user = get_user_from_session(request, state_store)
    if not user:
        logger.warning("Unauthorized access attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user