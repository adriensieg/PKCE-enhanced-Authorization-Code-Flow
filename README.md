

## OAuth 2.0 with PKCE Flow:

### Authorization Code Flow with PKCE (S256 method)
- PKCE (Proof Key for Code Exchange) adds a `code_verifier` and `code_challenge` to bind the code to the client
- JWT validation (signature, claims: `exp`, `aud`, `iss`, `nonce`, `azp`)
- State parameter for CSRF protection
- Access tokens, refresh tokens, ID tokens (and id_token usage)
- Microsoft Entra ID integration
- Use of requests for token exchange (HTTP client)
  
### Session Security:
- 1-hour session timeout
- Cookie attributes (`SameSite`, `Path`, `Secure`, `HttpOnly`)
- Server-side session storage
- Automatic session cleanup
- Session management (Starlette `SessionMiddleware` and `request.session`)
- In-memory `StateStore` backup + threading lock

### Comprehensive Security Headers:
- Content Security Policy (CSP)
- `X-Content-Type-Options`, `X-Frame-Options`
- Strict-Transport-Security (HSTS)
- Cache-Control for sensitive pages

### Rate Limiting & DoS Protection:
- 200 requests/day, 50 requests/hour per IP
- Special limits for authentication endpoints
- SlowAPI integration with FastAPI

### Additional Security:
- CORS middleware and allowed origins
- Trusted host middleware
- Comprehensive logging
- Logging (level DEBUG, sensitive logs)
- Debug endpoints & `/debug-info` page
- Health endpoint `/health`
- Error handlers and exception handling (custom 404/500 pages)
- Use of `secrets` & `cryptographic` randomness
  - High entropy randomness for `state`, `code_verifier`, `tokens`.



