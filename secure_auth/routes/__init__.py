"""Authentication and debug routes."""

from .auth import router as auth_router
from .debug import router as debug_router

__all__ = ['auth_router', 'debug_router']