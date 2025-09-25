## OAuth 2.0 with PKCE Flow:

How to generate a secret? 

```python
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_urlsafe(32)}')"
```

## Concepts in this tutorial

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
 

## Code / tokens

| Token/Code                    | Purpose                 | Real-life Value               | 
| ----------------------------- | ----------------------- | ----------------------------- |
| `code_verifier`               | PKCE secret             | Prevent code theft            |
| `code_challenge`              | PKCE hash               | Links request to verifier     |
| `state`                       | CSRF protection         | Prevents CSRF attacks         |
| `nonce`                       | OIDC replay protection  | ID token bound to request     |
| `authorization code` (`code`) | Temporary grant         | Exchange for tokens           |
| `access_token`                | API authorization       | Call protected resources      |
| `refresh_token`               | Refresh access token    | Keep user logged in           |
| `id_token`                    | User identity           | Know user info                |
| `session cookie`              | Store user/session data | Maintain login state          | 
| JWKS                          | Token verification      | Ensure ID token is legitimate |

### 1. `code_verifier`
- **What**: A cryptographically random secret used by the **client to prove it initiated the auth request (PKCE).**
- **Purpose**: It proves to the **authorization server** that the **token request** is **coming from the same client** that started the authorization request (PKCE security). Prevents **“authorization code interception” attacks**, especially for **public clients** (mobile apps, SPAs, or when session cookies might be exposed).
- **How produced (in our code)**: `base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')`

```
code_verifier = "qH1a8fGkL3v9Y2Q0bTf7PzUoWc4mR5xA6n_0XyZq-1"
```

### 2. `code_challenge` (S256)
- **What**: Derived from code_verifier (SHA256 + base64url). Sent to the authorization server in the initial request.
- **Purpose**: Tells the authorization server how to check the `code_verifier` later. Only the holder of `code_verifier` can correctly respond. Links the initial authorization request with the token request securely.
- **How**: `code_challenge = base64url_encode( SHA256(code_verifier) ).rstrip('=')`
- **Example derivation (pseudocode)**:
```
digest = SHA256("qH1a8fGkL3v9Y2Q0...")
code_challenge = base64url(digest).rstrip("=")
code_challenge = "X8h6s9V6y2tQW3xLaFzPq7eU-3jBv1yY9Rkz4dQwHqM"
```

### 3. `state`
- **What**: Random string generated at start, **stored in session and backup store**. 
- **Purpose**: CSRF protection token — ensures the response coming to `/auth/callback` was initiated by the same client. — random value tied to the auth request.
- **How produced (in our code)**: `secrets.token_urlsafe(32) (or generate_state()).`

```
state = "u2FhKs0QfX7Z9qYb3LpTg4v8r1wHj6N_aP0s"
```
**Cross-Site Request Forgery**: **CSRF attack** leverages the **implicit trust** placed in **user session cookies** by many web applications.
In these applications, **once the user authenticates**, **a session cookie is created** and **all subsequent transactions for that session are authenticated** using that cookie including potential actions initiated by an attacker by “riding” the existing session cookie. Due to this reason, CSRF is also called **“Session Riding”**.

http://reflectoring.io/complete-guide-to-csrf/

### 4. `nonce`
- **What**: OIDC nonce to **:bind `ID token` to `request`**: — prevents token replay. Random string stored in session and sent in the authorization request.
- **How**: `secrets.token_urlsafe(...)` (server generates, stores in session and sends in authorization request).
- **Purpose**: OIDC security; binds the `id_token` to the request, **:prevents replay attacks**:. Ensures the `id_token` is generated for this specific login request, not reused by an attacker. If missing - our `id_token` could be replayed by an attacker to **:impersonate a user**:.
- **Example**:
```
nonce = "n8SxT2v9dQ7_aB4mYwL0"
```

### 5. `Authorization Code` (code) — returned by authorization server
- **What**: **Short-lived**, **single-use code** returned to your `redirect_uri` **after the user authenticates and consents**.
- **Purpose / Goal**: Acts as **a temporary proof of user authentication**. It **allows the server** (**not the browser**) to **securely exchange it for tokens**. This keeps sensitive tokens (like `access_token` or `id_token`) **out of the browser URL**. **Prevents exposing tokens to front-end JavaScript**, browser history, logs, or referrers. Adds an **extra layer of security** via Proof Key for Code Exchange (PKCE). If missing: We cannot get an `access_token` or `id_token`; login flow fails.
- **Format**: Opaque, **URL-safe string**.
- **Lifetime**: Short (usually a few minutes), single-use.
- **Example**:
```
code = "AQABAAIAAAAmK...Zx"  
```

### 6. `Access Token` — returned by token endpoint
- **What**: Token our app presents when calling our protected resources such APIs (resource server). Authorization credential — **proves the client has permission to access specific resources on behalf of the user**. Enables your app to **fetch user data** or call APIs **without asking the user to log in again**. If missing: The app cannot access APIs; calls return `401 Unauthorized`.
- **Example request (form-encoded)**:
```
POST https://login.microsoftonline.com/<TENANT>/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET   # optional in public clients
&grant_type=authorization_code
&code=AUTH_CODE_FROM_CALLBACK
&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback
&code_verifier=CODE_VERIFIER_VALUE
```

### 7. `Refresh Token` — included in token response
- **What**: Long-lived token that can be used to request new access_tokens without user interaction.
- **Purpose**: Keeps the user “logged in” seamlessly by renewing expired access tokens. Greatly improves user experience by avoiding repeated logins. If missing: Once the access_token expires, the user must log in again.
- **Example token response** (truncated):

```
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "eyJhbGciOiJ...",
  "refresh_token": "0.AAA...opaque.refresh.token...",
  "id_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### 8. `ID Token` (`id_token`) — OpenID Connect identity token
- **What**: A JWT that contains claims about the authenticated user.
- **Purpose**: **Authentication proof** — **tells your app who the user is**. Provides user identity (name, email, subject ID). Used for SSO and displaying logged-in user info. If missing: We cannot reliably identify the user, even if you have an access token. **Identifies the user (SSO, user info)**
- **Example payload claims**:
```
{
  "iss": "https://login.microsoftonline.com/<TENANT>/v2.0",
  "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "aud": "YOUR_CLIENT_ID",
  "exp": 1730000000,
  "iat": 1729996400,
  "nonce": "n8SxT2v9dQ7_aB4mYwL0",
  "name": "Alice Example",
  "preferred_username": "alice@example.com",
  "email": "alice@example.com"
}
```

### 9. `Access Token`
- **What**: Can be either opaque string or JWT depending on provider.
- **Purpose**: Always the same — to authorize API/ towards our resource server calls.
- **Opaque string**: Random string; must be introspected at the authorization server.
  
```
access_token = "0.AAAAABBBB.CCddEEfGh..."
```
- **JWT**: Self-contained token; can be validated locally.
```
access_token = "eyJraWQiOiJ...header.eyJzdWIiOi...payload.signature"
```

### 10. Refresh Token (Format)
- **What**: Always an opaque string (not JWT).
- **Purpose**: Allows token renewal without user login. Supports long-lived sessions (weeks/months). If missing: User re-authenticates whenever the access_token expires.
- **Example**:
```
refresh_token = "0.AAAABBBBCCCCDDDD1234abcd...long-opaque-string"
```

### 11. `Session Cookie` (default `request.session`)
- **What**: By default, `Starlette/SessionMiddleware` serializes session dict into a **signed cookie**.
- **Purpose**: Persists temporary state (e.g. code_verifier, oauth_state) between browser and server. Required for completing OAuth flows. If misused: Storing tokens here is risky (they live in the browser and can leak). Best practice = store server-side (DB/Redis).
- **Example (conceptual)**:
```
Set-Cookie: session="gAJ9cQE...signed_base64..." ; HttpOnly ; Secure ; SameSite=Lax
```

### 12. `JWKS` (JSON Web Key Set) — public signing keys
- **What**: JSON document containing public keys used to verify JWTs (id_token / JWT access_token).
- **Purpose**: Enables your app to validate tokens’ signatures without hardcoding keys. Provides cryptographic proof that tokens really came from the authorization server. If missing: You cannot safely trust any JWT — anyone could forge them.
- **Example**:
```
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "abcd1234",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQS...base64url-modulus...",
      "e": "AQAB"
    }
  ]
}
```
### The Three “Randoms” in OAuth2 / OIDC - what are the differences between `state`, `code_challenge`, `nonce`? 

| Name                                    | Purpose (technical)                                                                                                                      | Real-life metaphor                                                                                                                                                                                                                                                      | What happens if missing?                                                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **code\_challenge** (+ `code_verifier`) | Prevents *authorization code interception*. Ensures only the same client that started the flow can finish it. (PKCE)                     | Think of it like a **combination lock**. You give the server the lock pattern (`code_challenge`), and later you prove you know the key (`code_verifier`). Even if a thief steals the “receipt” (authorization code), they can’t open the lock without the matching key. | Attackers who steal the `code` could exchange it for tokens.                                                      |
| **state**                               | Prevents *cross-site request forgery (CSRF)* and correlates requests/responses. Ensures the callback belongs to a request *you started*. | Think of it like a **claim check at a coatroom**. You hand over your coat (auth request) and get a ticket (`state`). When you come back, only the person with the matching ticket gets the coat.                                                                        | Attacker could trick your app into accepting a login that it didn’t start, hijacking the session.                 |
| **nonce**                               | Protects *ID tokens* from replay or substitution. Ensures the ID token really belongs to this login attempt. (OpenID Connect-specific)   | Think of it like a **scratch-off code on a concert ticket**. The venue checks that the hidden code matches what they issued to you. Without it, someone could give you an old but valid ticket from a different event.                                                  | Replay attack: attacker could send you a stolen but valid `id_token` and your app would think it’s a fresh login. |

#### Why not just one?

Each exists because it protects against different attackers at different steps:
- **`state`** → **protects the browser <-> app redirect (CSRF).**
  - Your ticket purchase comes with a receipt number. When you show up, they check that your ticket matches the receipt you got. Prevents someone from handing you the wrong ticket.
- **`code_challenge`** → **protects the code <-> token exchange (PKCE).**
  - Your ticket also requires a personal PIN you set when buying. Even if someone steals the ticket on the way, they can’t use it without your PIN.
- **`nonce`** → **protects the ID token itself (identity replay).**
  - On the ticket itself is a one-time hologram code that proves it’s fresh for this concert only, not reused from last week’s show.

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


## Bibliography
- https://developer.reachfive.com/docs/flows/authorization-code-pkce.html
- https://docs.abblix.com/docs/openid-connect-flows-explained-simply-from-implicit-flows-to-authorization-code-flows-with-pkce-and-bff
