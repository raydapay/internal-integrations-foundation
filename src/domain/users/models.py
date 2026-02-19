from datetime import datetime

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    """Represents a system user authenticated via Google SSO.

    Attributes:
        id: Primary key identifier.
        email: Unique email address provided by Google.
        full_name: User's full name.
        avatar_url: URL to the user's Google profile picture.
        is_active: Boolean indicating if the user is permitted to access the system.
        is_superuser: Boolean indicating administrative privileges.
        created_at: Timestamp of account creation.
        last_login: Timestamp of the most recent successful authentication.
    """

    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    full_name: str
    avatar_url: str | None = None
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: datetime = Field(default_factory=datetime.utcnow)