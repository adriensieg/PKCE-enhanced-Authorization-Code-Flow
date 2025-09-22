## More concepts: 

- Tokens vs. Code
- Server flow vs. Implicit flow
- Bearer token
- Token types:
  - **Access tokens**: Lets clients call Google Cloud APIs
  - **Token-granting tokens**: Lets clients obtain new or different tokens, possibly at a later point in time.
  - **Identity tokens**: Lets clients identify the user they're interacting with.
  - https://cloud.google.com/docs/authentication/token-types
  - *User access token*
  - *Service account access token*
  - *Domain-wide delegation token*
  - *Service account JSON Web Token (JWT)*
  - *Federated access token*
  - *Credential access boundary token*
  - *Client-issued credential access boundary token*
 
- Client Assertions
- Token Revocation
- Introspection
- Resource indicators

- Traditional Cookie-Based Auth
- Modern Token Based Auth

<img width="75%" height="75%" alt="image" src="https://github.com/user-attachments/assets/aa7028bd-fe32-4d69-b554-32b4618c7033" />

- Should JWT Token be stored in a cookie, header or body?

<img width="75%" height="75%" alt="image" src="https://github.com/user-attachments/assets/c4ed6de1-c566-4cc8-9e27-504ff74de643" />

## Active Directory
- Active Directory Basics
- Breaching Active Directory
- Enumerating Active Directory
  - Reconnaissance
  - Initial Exploitation
  - Establish Foothold
  - Escalate Privileges
  - Internal Reconnaissance
  - Lateral Movement
  - Maintain Presence
  - Complete Mission
- Lateral Movement and Pivoting
- Exploiting Active Directory
- Persisting Active Directory
- Credentials Harvesting

https://tryhackme.com/module/hacking-active-directory

### `Server flow` vs. `Implicit flow`
The most commonly used approaches for authenticating a user and obtaining an ID token are called the "server" flow and the "implicit" flow. 
The server flow allows the backend server of an application to verify the identity of the person using a browser or mobile device. 
The implicit flow is used when a client-side application (typically a JavaScript app running in the browser) needs to access APIs directly instead of using its backend server.


https://medium.com/@shaheeryasirofficial/from-zero-to-adversary-an-advanced-red-teaming-road-map-for-beginners-c3d2e52a1f9f
