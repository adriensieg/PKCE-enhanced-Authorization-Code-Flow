## Improvements

1. **We do NOT fully validate the ID token.**
`validate_id_token()` currently uses `jwt.get_unverified_claims(id_token)` — that only reads claims without verifying `signature`, `issuer`, `audience`, `expiration`, or `nonce`. 
This is unsafe. We must fetch Microsoft’s JWKS and verify the JWT signature and claims (iss, aud, exp, nonce).

2. **We did not use or validate a `nonce`**.
For OpenID Connect you should send a nonce in the authorization request and verify the same nonce claim in the id_token. This prevents replay attacks on the ID token.

3. **Session storage is client-side by default (cookie)**.
With Starlette’s default SessionMiddleware, request.session is serialized into a cookie (signed but not encrypted). That means code_verifier, access_token, and refresh_token may be stored in the browser cookie. That is risky. Use a server-side session store (Redis, database) or encrypt server-side.

4. **We log sensitive data**.
The code logs request.session, request.cookies, and token info in debug. Don’t log tokens, code_verifier, client_secret, or full session data.

6. **No token refresh logic implemented**.
We store refresh_token but do not refresh access tokens when they expire. Add a refresh flow (POST grant_type=refresh_token) and maintain expiry (expires_in).

7. **Blocking I/O in async routes**.
You use requests.post inside async endpoints. requests is synchronous and will block the event loop. Use an async HTTP client (e.g., httpx.AsyncClient) or run blocking calls in a threadpool.

8. **`StateStore` is in-memory, not suitable for multiple instances**.
Your StateStore is process memory. If you run multiple app instances, session or backup lookups will fail. Use Redis or other shared store for state/code_verifier backup.

9. **Cookie flags for production**.
In production, set session cookie `Secure=True`, `HttpOnly=True`, and appropriate `SameSite`. Use HTTPS and set `https_only=True` for `SessionMiddleware`.

10. **No signature/claim checks for ID tokens and no audience/issuer validation**.
See #1. Check aud equals `CLIENT_ID`, iss equals Microsoft issuer for your tenant, exp not expired, etc.

11. **No CSRF/extra checks beyond state**.
state is good, but validate strictly. Currently if state mismatches you don't fail immediately — you try backup. That is OK to handle session loss, but be careful and log carefully.

12. **No nonce handling for ID token**.
See #2. Add nonce both for security and correct OIDC usage.

13. **Logout token revocation not implemented**.
You redirect to Microsoft logout, but you may also want to revoke refresh tokens at the token revocation endpoint on logout.

14. Timezones / datetime usage.
We use naive datetime with `utcnow()` and `fromisoformat()`; **being explicit about timezone (aware datetimes) avoids subtle bugs**.
