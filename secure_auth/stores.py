"""State store and JWKS cache implementations."""

import threading
import logging
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)


class StateStore:
    """Enhanced state store that acts as a session replacement."""
    
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
    
    def get_and_remove_state(self, state: str) -> Tuple[str, str]:
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
    
    def get_and_remove_temp_data(self, key: str) -> Tuple[str, str]:
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


class JWKSCache:
    """JWKS cache for token validation."""
    
    def __init__(self):
        self._cache = {}
        self._last_fetch = {}
        self._lock = threading.Lock()
        self.cache_duration = timedelta(hours=1)  # Cache for 1 hour
    
    def get_jwks(self, jwks_url: str) -> dict:
        """Get JWKS from cache or fetch if needed."""
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