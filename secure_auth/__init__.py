"""Secure OAuth Authentication Library for FastAPI."""

from .config import Settings, get_settings
from .stores import StateStore, JWKSCache
from .middleware import setup_middleware, setup_error_handlers

__all__ = ['Settings', 'get_settings', 'StateStore', 'JWKSCache', 'setup_middleware', 'setup_error_handlers']