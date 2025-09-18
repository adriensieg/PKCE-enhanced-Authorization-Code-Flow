## OAuth 2.0 with PKCE Flow:

## Concepts

### Authorization Code Flow with PKCE (S256 method)
- PKCE (Proof Key for Code Exchange) adds a `code_verifier` and `code_challenge` to bind the code to the client
  - **Code verifier generation** (random 32 bytes, base64 encoded)
  - **Code challenge creation** (SHA256 hash of verifier)
  - **Server-side verification** during token exchange
- **JWT validation** (signature, claims: `exp`, `aud`, `iss`, `nonce`, `azp`)
- **State** parameter for **CSRF** protection
- **Access tokens**, **refresh tokens**, **ID tokens** (and `id_token` usage)
  - **Access Token**: JWT format, ~1500+ characters, expires in 1 hour
  - **ID Token**: JWT with user claims (sub, name, email, etc.)
  - **Refresh Token**: Opaque string, ~2000 characters, expires in ~90 days
  - **Authorization Code**: Temporary code, ~2000 characters, expires in 10 minutes
- Microsoft Entra ID integration
- Use of `requests` for **token exchange** (HTTP client)
  
### Session Security:
- 1-hour session timeout
- **Cookie attributes** (`SameSite`, `Path`, `Secure`, `HttpOnly`)
- **Server-side session storage**
- **Automatic session cleanup**
- **Session Recovery Mechanism**: fallback from session storage to **in-memory state store**
  - In-memory `StateStore` backup + threading lock
- **Session management** (Starlette `SessionMiddleware` and `request.session`)

### Comprehensive Security Headers:
- Content Security Policy (CSP)
- `X-Content-Type-Options`, `X-Frame-Options`
- Strict-Transport-Security (HSTS)
- **Cache-Control** for sensitive pages

### Rate Limiting & DoS Protection:
- 200 requests/day, 50 requests/hour per IP
  - Use of `get_remote_address` for IP-related checks
- Special limits for authentication endpoints
- SlowAPI integration with FastAPI

### Additional Security:
- **CORS middleware** and **allowed origins**
- Trusted host middleware
- Comprehensive **logging**
- Logging (level DEBUG, sensitive logs)
- Debug endpoints & `/debug-info` page
- Health endpoint `/health`
- Error handlers and exception handling (custom 404/500 pages)
- Use of `secrets` & `cryptographic` randomness
  - High entropy randomness for `state`, `code_verifier`, `tokens`.

## Deep dive

#### StateStore 
`StateStore` class is a **thread-safe**, **temporary in-memory storage** for "states" with associated metadata (a code verifier + timestamp)

Race condition occurs when multiple threads or processes read and write the same variable i.e. they have access to some shared data and they try to change it at the same time. In such a scenario threads are “racing” each other to access/change the data.

```python
class StateStore:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        
    def set_state(self, state: str, code_verifier: str):
        with self._lock:
            self._store[state] = {
                'code_verifier': code_verifier,
                'timestamp': datetime.utcnow()
            }
            # Clean up old entries (older than 10 minutes)
            cutoff = datetime.utcnow() - timedelta(minutes=10)
            self._store = {k: v for k, v in self._store.items() 
                          if v['timestamp'] > cutoff}
            logger.debug(f"State store now has {len(self._store)} entries")
    
    def get_and_remove_state(self, state: str) -> str:
        with self._lock:
            data = self._store.pop(state, None)
            if data:
                logger.debug(f"Retrieved state from backup store")
                return data['code_verifier']
            logger.debug(f"State not found in backup store")
            return None
```

- `self._store`: A dictionary that holds state entries.


- Race Condition, Deadlock and Threat Block




## The flow

```mermaid
sequenceDiagram
    participant User as User Browser
    participant App as FastAPI App
    participant Session as Session Store
    participant Backup as Backup State Store
    participant MS as Microsoft Entra ID
    participant Token as Token Endpoint

    Note over User, Token: OAuth 2.0 PKCE Flow - Complete Process

    %% 1. Initial Access
    User->>App: GET /
    App->>Session: Check for user session
    Session-->>App: No user found
    App-->>User: 200 OK - Home page (anonymous)

    %% 2. Login Initiation
    User->>App: Click "Login with Microsoft"
    App->>App: GET /login
    App-->>User: 200 OK - Login page

    %% 3. OAuth Flow Initiation
    User->>App: Click "Sign in with Microsoft"
    App->>App: GET /auth/microsoft
    
    %% 4. PKCE Generation
    Note over App: Generate PKCE Parameters
    App->>App: code_verifier = base64(random_32_bytes)<br/>Format: "wF3n_MM-UpaCfPebO_GD4yG91uJNsU6ptaKsAYagO5M"
    App->>App: code_challenge = base64(sha256(code_verifier))<br/>Format: "EboEzGmFj2DW-whIFq6wv_0XgZ2gJASLdpQv5dme1c4"
    App->>App: state = random_32_bytes<br/>Format: "n1w24kbvPQqZb59EfAmUdoFWDma5BW-DQwuFplZTCa4"

    %% 5. Store State (Dual Storage)
    App->>Session: Store code_verifier & oauth_state
    App->>Backup: Store state -> code_verifier mapping
    Note over Backup: Backup: {"n1w24k...": {"code_verifier": "wF3n...", "timestamp": "2025-09-18T14:34:18Z"}}

    %% 6. Build Authorization URL
    Note over App: Build Authorization URL
    App->>App: auth_url = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"<br/>+ "?client_id=d95e0397-1de4-4434-a540-3aa5e3c73c94"<br/>+ "&response_type=code"<br/>+ "&redirect_uri=http://localhost:8080/auth/callback"<br/>+ "&scope=openid profile email"<br/>+ "&state=n1w24kbvPQqZb59EfAmUdoFWDma5BW-DQwuFplZTCa4"<br/>+ "&code_challenge=EboEzGmFj2DW-whIFq6wv_0XgZ2gJASLdpQv5dme1c4"<br/>+ "&code_challenge_method=S256"<br/>+ "&response_mode=query"

    App-->>User: 302 Redirect to Microsoft

    %% 7. Microsoft Authentication
    User->>MS: GET /oauth2/v2.0/authorize (with PKCE params)
    MS-->>User: 200 OK - Microsoft Login Page
    User->>MS: Enter credentials
    MS->>MS: Validate user credentials
    MS->>MS: Validate client_id & redirect_uri
    MS->>MS: Store code_challenge for later verification

    %% 8. Authorization Code Generation
    Note over MS: Generate Authorization Code
    MS->>MS: authorization_code = "1.ARIATCcX37b_90WE0xd658a9H..."<br/>(~2000 characters, expires in 10 minutes)
    MS-->>User: 302 Redirect to callback with code & state

    %% 9. Callback Handling
    User->>App: GET /auth/callback?code=1.ARIATCcX...&state=n1w24k...
    App->>Session: Check for oauth_state
    Session-->>App: Session empty (session lost!)
    
    Note over App: Session Recovery Process
    App->>App: session_state = None, received_state = "n1w24k..."
    App->>App: Log: "State mismatch - Session: None, Received: n1w24k..."
    App->>Session: Get code_verifier from session
    Session-->>App: None (session lost)
    App->>Backup: Get code_verifier using received state
    Backup-->>App: "wF3n_MM-UpaCfPebO_GD4yG91uJNsU6ptaKsAYagO5M"
    App->>App: Log: "Retrieved state from backup store"
    App->>Backup: Remove used state entry

    %% 10. Token Exchange
    Note over App: Prepare Token Exchange
    App->>App: token_data = {<br/>  "client_id": "d95e0397-1de4-4434-a540-3aa5e3c73c94",<br/>  "client_secret": "5Mj8Q~IuFrRrnAuGeAWnEnmsQQSXZwOAmitc1csz",<br/>  "code": "1.ARIATCcX37b_90WE0xd658a9H...",<br/>  "redirect_uri": "http://localhost:8080/auth/callback",<br/>  "grant_type": "authorization_code",<br/>  "code_verifier": "wF3n_MM-UpaCfPebO_GD4yG91uJNsU6ptaKsAYagO5M"<br/>}

    App->>Token: POST /oauth2/v2.0/token (with PKCE verification)
    
    Note over Token: Token Validation Process
    Token->>Token: 1. Validate authorization_code (not expired, not used)
    Token->>Token: 2. Validate client_id & client_secret
    Token->>Token: 3. Validate redirect_uri matches registration
    Token->>Token: 4. PKCE Verification:<br/>   - Get stored code_challenge<br/>   - Calculate sha256(code_verifier)<br/>   - Compare with code_challenge<br/>   - Must match exactly
    Token->>Token: 5. Generate tokens if all validations pass

    %% 11. Token Response
    Note over Token: Generate Token Response
    Token->>Token: access_token = JWT with user claims<br/>expires_in = 3600 seconds
    Token->>Token: id_token = JWT with user identity<br/>Contains: sub, name, email, preferred_username
    Token->>Token: refresh_token = Opaque string for token refresh<br/>expires_in = ~90 days

    Token-->>App: 200 OK + Token JSON:<br/>{<br/>  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",<br/>  "token_type": "Bearer",<br/>  "expires_in": 3600,<br/>  "scope": "openid profile email",<br/>  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",<br/>  "refresh_token": "1.ARIATCcX37b_90WE0xd658a9H..."<br/>}

    %% 12. ID Token Validation
    Note over App: ID Token Processing
    App->>App: Parse ID token header (unverified)
    App->>App: Parse ID token payload (unverified)<br/>payload = {<br/>  "sub": "AAAAAaaaAAA-UserObjectId",<br/>  "name": "John Doe",<br/>  "preferred_username": "john.doe@company.com",<br/>  "email": "john.doe@company.com",<br/>  "exp": 1726677261,<br/>  "iat": 1726673661,<br/>  "aud": "d95e0397-1de4-4434-a540-3aa5e3c73c94",<br/>  "iss": "https://login.microsoftonline.com/{tenant}/v2.0"<br/>}
    App->>App: Basic validation (expiry check)
    App->>App: Extract user information

    %% 13. Session Creation
    Note over App: Create User Session
    App->>App: user_data = {<br/>  "sub": "AAAAAaaaAAA-UserObjectId",<br/>  "name": "John Doe",<br/>  "email": "john.doe@company.com",<br/>  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGci...",<br/>  "refresh_token": "1.ARIATCcX37b_90WE0xd658a9H..."<br/>}
    App->>Session: Store user_data & login_time
    App->>Session: Remove oauth_state & code_verifier (cleanup)

    App-->>User: 302 Redirect to /

    %% 14. Authenticated Access
    User->>App: GET /
    App->>Session: Check for user session
    Session-->>App: Return user_data
    App->>App: Check login_time < 1 hour (session validity)
    App-->>User: 200 OK - Home page (authenticated)<br/>Display: "Welcome, John Doe"

    %% 15. Protected Resource Access
    User->>App: GET /debug-info
    App->>Session: Check authentication (get_current_user)
    Session-->>App: Return user_data
    App-->>User: 200 OK - Debug page with user info

    %% 16. Logout Process
    User->>App: GET /logout
    App->>Session: Clear all session data
    App-->>User: 302 Redirect to Microsoft logout:<br/>"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout<br/>?post_logout_redirect_uri=http://localhost:8080/logout-complete"
    User->>MS: Microsoft logout
    MS-->>User: 302 Redirect to /logout-complete
    User->>App: GET /logout-complete
    App-->>User: 200 OK - Logout confirmation page

    %% Error Scenarios
    Note over User, Token: Common Error Scenarios

    %% Session Loss Scenario (Already shown above in step 9)
    
    %% Invalid State Scenario
    rect rgb(255, 240, 240)
        Note over App: Error: Invalid State Parameter
        App->>App: If state doesn't match any stored state
        App-->>User: 302 Redirect /login?error=invalid_state
    end

    %% Token Exchange Errors
    rect rgb(255, 240, 240)
        Note over Token: Error: PKCE Verification Failed
        Token->>Token: sha256(received_code_verifier) ≠ stored_code_challenge
        Token-->>App: 400 Bad Request: "invalid_grant"
    end

    rect rgb(255, 240, 240)
        Note over Token: Error: Client Configuration Mismatch
        Token->>Token: Public client + client_secret provided
        Token-->>App: 401 Unauthorized: "AADSTS700025"
    end
```

## Improvements:
- **Rotate** all exposed credentials now and treat them as compromised.
- Implement **proper JWT verification** using JWKS, `check` `exp`, `aud`, `iss`.
- Move secrets to **a secret manager**; do not hardcode secrets in repo.
- Set **secure cookie flags** in production: `Secure=True`, `HttpOnly=True`, `SameSite=Lax/Strict`.
- **Harden CSP** and **remove** `'unsafe-inline' / *; use nonces/hashes.`
- **Disable verbose DEBUG logging** in prod; redact tokens and sensitive fields in logs.
- **Remove or protect debug endpoints** — **restrict to internal networks or admin roles**.
- Use a **distributed store for state & rate limiter (Redis) for scaling**.
- Validate **redirect URIs** & protect against open redirects.
- **Implement token revocation** on logout if supported by provider.
- **Add automated tests** and **CI checks** to prevent **insecure defaults** from being merged.
- **Use TLS everywhere** (`https_only=True`) and enforce **HSTS in production**.

## Bibliography
- https://developer.reachfive.com/docs/flows/authorization-code-pkce.html
- https://docs.abblix.com/docs/openid-connect-flows-explained-simply-from-implicit-flows-to-authorization-code-flows-with-pkce-and-bff
