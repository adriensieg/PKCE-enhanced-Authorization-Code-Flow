
## Understanding SECRET_KEY
The SECRET_KEY is used for:
- Session encryption/decryption
- CSRF protection
- Cryptographic operations

It should be:
- Cryptographically secure (high entropy)
- 32+ characters long
- Kept secret (never commit to version control)
- Different for each environment

How to generate it? 
```python
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_urlsafe(32)}')"
```