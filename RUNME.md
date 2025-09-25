
### Public Client vs. Private Client

### Multi-tenant vs. Single-tenant

### Access tokens (used for implicit flows) vs. ID tokens (used for implicit and hybrid flows)

### Configure Platforms

Microsoft has different OAuth flow restrictions:

SPA: Must use browser-based CORS requests (JavaScript fetch/XMLHttpRequest)
Mobile/Desktop (PublicClient): Allows server-side token exchange with PKCE
Web: Requires client authentication (secret/certificate)


# Public Client

# 1. Azure AD Configuration Changes Required
### 1. Enable Public Client Flows
- In our Azure AD app registration:
- Go to Authentication → Advanced settings
- Set "Allow public client flows" to Yes
This is the crucial setting that tells Azure AD this app can use PKCE without a client secret

### 2. Verify Platform Configuration
- In Authentication → Platform configurations
- Make sure you have a Mobile/Desktop platform configured
- Add redirect URI: `http://localhost:8080/auth/callback`
- Enable ID tokens checkbox

If we chose Web platform configured (not Mobile/Desktop) - we should have this issue "Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests."
This means Microsoft expects SPA applications to make token requests from the browser using CORS, not from a server-side application. 
Our FastAPI app is making a server-to-server POST request, which Microsoft blocks for SPA platform types.
Since our FastAPI app makes server-side HTTP requests (not browser CORS requests), you need the Mobile/Desktop platform type, which allows public clients to make server-side token requests with PKCE protection.

Change our manifest from:

```
"replyUrlsWithType": [
    {
        "url": "http://localhost:8080/auth/callback",
        "type": "Spa"
    }
]
```
To:

```
"replyUrlsWithType": [
    {
        "url": "http://localhost:8080/auth/callback",
        "type": "PublicClient"
    }
]
```

### 3. Remove Any Client Secrets (Optional)
- Go to Certificates & secrets
- You can delete any existing client secrets since they won't be used

### 4. Verify API Permissions

In API permissions, ensure you have:

openid
profile
email
offline_access
