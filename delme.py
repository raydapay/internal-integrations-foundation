import secrets

# Generates a random URL-safe string (Base64 encoded)
# The default nbytes (16) is sufficient for most use cases
secure_token = secrets.token_urlsafe()
print(secure_token)
