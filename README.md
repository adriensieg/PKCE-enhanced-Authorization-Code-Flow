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
 
## The flow

1. **User visits the app and clicks "login".** The browser makes a request to your FastAPI app (e.g. `/auth/microsoft`).
   
3. Server generates **PKCE** and **state values**. The app (server code) generates:
  - a `code_verifier` (**random secret**),
  - a `code_challenge` (**SHA256** of the verifier),
  - a `state` (CSRF guard).
These values are created **on the server**, **not by the remote authorization server**.

3. The server stores **those values in two places**.
  - It stores them in `request.session` (**Starlette session**). Important: with Starlette's default `SessionMiddleware`, **session data is serialized into a cookie** and **sent to the browser** (signed but not encrypted).
  - It also stores {`state` -> `code_verifier`, `timestamp`} in **an in-memory** `StateStore` as a server-side backup.
    
4. Server **builds the authorization URL** and **redirects the user's browser**.
The URL includes
  - `client_id`,
  - `response_type=code`,
  - `redirect_uri`,
  - `scope`,
  - `state`,
  - `code_challenge`, and
  - `code_challenge_method=S256`.
The browser is redirected to **Microsoft’s authorization endpoint**.

6. **User authenticates & consents at Microsoft**.
Microsoft prompts the user to **sign in/consent**. The authorization server **records the authorization grant**, including the `code_challenge` and `state` **associated with that authorization request**, so it can verify them later when the code is exchanged.

7. **Authorization server redirects the browser** back to your `callback` with `code` and `state`.
Microsoft sends the browser back to `REDIRECT_URI` (our `/auth/callback`) with **query parameters like ?code=...&state=....**

8. Your **callback retrieves** `state` and `code_verifier`, then **exchanges the code for tokens**.
  - The callback checks the `state` against the `session oauth_state` (and — if the session was lost — it looks up the `code_verifier` in the **in-memory** `StateStore` backup).
  - It retrieves the `code_verifier` (from **session** or **backup**) and then makes a server-side POST to the token endpoint with:
    - `client_id`,
    - `client_secret`,
    - `code`,
    - `redirect_uri`,
    - `grant_type=authorization_code`, and
    - `code_verifier`.

8. **Authorization server validates the token request**.
The **auth server verifies the authorization code**, ensures the `code_verifier` matches the previously stored `code_challenge`, verifies the `client_id` (and `client_secret` if provided), and checks redirect URI, etc.

9. **If valid, the token endpoint returns tokens**.
Microsoft returns `access_token`, `id_token` (because we asked for openid), and usually `refresh_token` and `expires_in`.

10. **Our app decodes/uses the ID token and stores user info**.
In the code we call `validate_id_token()` then put **user info** and **tokens** into `request.session` and set `login_time`. We then clear `code_verifier` and `oauth_state` from the **session** and redirect the user to `/`.

11. **The app can use the access token to call our services**.
When we need protected resources, use the `access_token` in `Authorization headers`. When the token expires, use the `refresh_token` **to get a new access token**.

```mermaid
sequenceDiagram
    autonumber
    participant Browser as End-user (Browser)
    participant App as Your FastAPI App (Server)
    participant Session as Session Cookie (Client-side)
    participant Backup as StateStore (Server-side)
    participant Authz as Authorization Server (Microsoft)
    participant Token as Token Endpoint (Microsoft)
    participant Resource as Resource Server (API)

    Browser->>App: GET /auth/microsoft (user clicks "Login")
    App->>App: generate code_verifier, code_challenge = S256(code_verifier), state, nonce
    App->>Session: set session['code_verifier'], session['oauth_state'], session['oidc_nonce']  (stored into cookie)
    App->>Backup: set_state(state, code_verifier)  // server-side backup store
    App-->>Browser: 302 Redirect to Authz?client_id=...&response_type=code&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256&nonce=...
    Browser->>Authz: Authorization Request (user authenticates & consents at Microsoft)
    Authz-->>Browser: 302 Redirect to REDIRECT_URI?code=AUTH_CODE&state=STATE
    Browser->>App: GET /auth/callback?code=AUTH_CODE&state=STATE
    App->>Session: read session['oauth_state'] and session['code_verifier']
    alt session has code_verifier
        App->>Token: POST /token {client_id, client_secret, grant_type=authorization_code, code=AUTH_CODE, redirect_uri, code_verifier}
    else session is lost / cookie cleared
        App->>Backup: get_and_remove_state(state) -> code_verifier
        App->>Token: POST /token {client_id, client_secret, grant_type=authorization_code, code=AUTH_CODE, redirect_uri, code_verifier}
    end
    Token-->>App: 200 OK {access_token, refresh_token, id_token, expires_in, scope, token_type}
    App->>App: validate id_token (fetch JWKS, verify signature, validate iss/aud/exp/nonce)
    App->>Session: store user info + tokens; remove PKCE/session oauth_state
    App-->>Browser: 302 Redirect to / (user is now authenticated)
    Note over App,Resource: Later: App calls Resource with Authorization: Bearer <access_token>
    Resource-->>App: 200 OK (protected resource)
    alt access_token expired
        App->>Token: POST /token {grant_type=refresh_token, refresh_token=...} -> new access_token
    end
```



## Deep dive

#### StateStore 
`StateStore` class is a **thread-safe**, **temporary in-memory storage** for "states" with associated metadata (a **code verifier** + **timestamp**)
The `StateStore` saves the `code_verifier` temporarily (along with the `state`) so that later, **when the redirect comes back**, our app **can retrieve it and complete the token exchange**.

`code_verifier` is a **random**, **high-entropy string** (like a long random password) **generated by our app** before redirecting **the user to the identity provider** (e.g., Google, Auth0).
From the code verifier, **our app derives a code challenge** (usually by applying SHA-256 and Base64 URL encoding).

**Race condition** occurs when **multiple threads or processes read** and **write the same variable** i.e. they have access to some shared data and they try to change it at the same time. In such a scenario threads are “racing” each other to access/change the data.

```python
class StateStore:
    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

# self._store: A dictionary that holds state entries.
# self._lock: A threading lock to ensure thread safety (so multiple threads don’t modify the store at the same time).
        
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

- Race Condition, Deadlock and Threat Block

### Code verifier
`code verifier` is only known to the client (our app), and we’ll need it later to finish the flow:

- **Step 1** – Start Auth Request
  - Our app generates a `state` and a `code verifier`.
  - It stores the `code verifier` temporarily (in memory, DB, or a structure like our StateStore).
  - It derives a `code challenge` and sends it to the **identity provider** with the **state**.

``` shell
/authorize?client_id=...&state=XYZ&code_challenge=HASH(verifier)&...
```

- **Step 2 – User Authenticates**
  - The user logs in at the provider.
  - The provider redirects back to our app with the `state` and an `authorization code`.

``` shell
/callback?state=XYZ&code=AUTH_CODE
```

- **Step 3 – Token Exchange**
  - Our app **retrieves the stored code verifier** for that state.
  - It sends the `AUTH_CODE` + `code_verifier` to the provider’s token endpoint.

``` shell
POST /token
{
  "code": "AUTH_CODE",
  "code_verifier": "ORIGINAL_RANDOM_STRING"
}
```
- The provider **recomputes the hash** from **our verifier** and checks it against the `code_challenge` from Step 1.
- If they match → we’re the legitimate client → we get tokens (access/refresh).

## The flow

## Improvements

1. You do NOT fully validate the ID token.
validate_id_token() currently uses jwt.get_unverified_claims(id_token) — that only reads claims without verifying signature, issuer, audience, expiration, or nonce. This is unsafe. You must fetch Microsoft’s JWKS and verify the JWT signature and claims (iss, aud, exp, nonce).

2. You did not use or validate a nonce.
For OpenID Connect you should send a nonce in the authorization request and verify the same nonce claim in the id_token. This prevents replay attacks on the ID token.

3. Session storage is client-side by default (cookie).
With Starlette’s default SessionMiddleware, request.session is serialized into a cookie (signed but not encrypted). That means code_verifier, access_token, and refresh_token may be stored in the browser cookie. That is risky. Use a server-side session store (Redis, database) or encrypt server-side.

4. You log sensitive data.
The code logs request.session, request.cookies, and token info in debug. Don’t log tokens, code_verifier, client_secret, or full session data.

5. Client secret hardcoded in source.
Do not store CLIENT_SECRET (or SECRET_KEY) in code. Use environment variables or a secret manager.

6. No token refresh logic implemented.
You store refresh_token but do not refresh access tokens when they expire. Add a refresh flow (POST grant_type=refresh_token) and maintain expiry (expires_in).

7. Blocking I/O in async routes.
You use requests.post inside async endpoints. requests is synchronous and will block the event loop. Use an async HTTP client (e.g., httpx.AsyncClient) or run blocking calls in a threadpool.

8. StateStore is in-memory, not suitable for multiple instances.
Your StateStore is process memory. If you run multiple app instances, session or backup lookups will fail. Use Redis or other shared store for state/code_verifier backup.

9. Cookie flags for production.
In production, set session cookie Secure=True, HttpOnly=True, and appropriate SameSite. Use HTTPS and set https_only=True for SessionMiddleware.

10. No signature/claim checks for ID tokens and no audience/issuer validation.
See #1. Check aud equals CLIENT_ID, iss equals Microsoft issuer for your tenant, exp not expired, etc.

11. No CSRF/extra checks beyond state.
state is good, but validate strictly. Currently if state mismatches you don't fail immediately — you try backup. That is OK to handle session loss, but be careful and log carefully.

No nonce handling for ID token.

See #2. Add nonce both for security and correct OIDC usage.

Logout token revocation not implemented.

You redirect to Microsoft logout, but you may also want to revoke refresh tokens at the token revocation endpoint on logout.

Timezones / datetime usage.

You use naive datetime with utcnow() and fromisoformat(); being explicit about timezone (aware datetimes) avoids subtle bugs.

## Bibliography
- https://developer.reachfive.com/docs/flows/authorization-code-pkce.html
- https://docs.abblix.com/docs/openid-connect-flows-explained-simply-from-implicit-flows-to-authorization-code-flows-with-pkce-and-bff
