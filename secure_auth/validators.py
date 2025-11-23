"""Token validation functions."""

import time
import logging
from typing import Dict, Any
from fastapi import HTTPException
from jose import JWTError, jwt, jwk

logger = logging.getLogger(__name__)


async def validate_id_token(
    id_token: str, 
    expected_nonce: str, 
    jwks_cache, 
    jwks_url: str, 
    client_id: str, 
    tenant_id: str
) -> Dict[str, Any]:
    """Validate ID token with proper JWT verification using python-jose."""
    try:
        # Get the header to find the key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get('kid')
        
        if not kid:
            raise ValueError("No key ID in token header")
        
        # Get JWKS
        jwks_data = jwks_cache.get_jwks(jwks_url)
        
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
            f"https://sts.windows.net/{tenant_id}/",
            f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        ]
        
        # Try with the actual issuer first
        issuer_to_use = actual_issuer if actual_issuer in expected_issuers else expected_issuers[0]
        
        # Verify and decode the token
        try:
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=['RS256'],
                audience=client_id,
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
                    audience=client_id,
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