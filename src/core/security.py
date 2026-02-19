from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

from src.config.settings import settings

# We bridge Pydantic settings to Starlette's Config interface expected by Authlib
config_data = {
    "GOOGLE_CLIENT_ID": settings.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": settings.GOOGLE_CLIENT_SECRET,
}
starlette_config = Config(environ=config_data)

oauth = OAuth(starlette_config)

oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

def get_oauth() -> OAuth:
    """Retrieves the configured Authlib OAuth instance.

    Returns:
        OAuth: The registered OAuth client for Google SSO.
    """
    return oauth