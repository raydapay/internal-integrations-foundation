import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from fastapi.responses import RedirectResponse
from starlette.datastructures import URL

from src.domain.users.models import User, UserRole
from src.domain.users.router import auth_google, login, logout


class TestUsersRouter(unittest.IsolatedAsyncioTestCase):
    """Test suite for the Google SSO JIT provisioning and session management."""

    def setUp(self) -> None:
        """Initializes mock HTTP requests and database sessions."""
        self.mock_request = MagicMock()
        self.mock_request.session = {}
        # Ensure _get_https_redirect_uri formats correctly
        self.mock_request.url_for.return_value = URL("http://gateway.local/auth/google")
        self.mock_request.headers = {"x-forwarded-proto": "https"}

        self.mock_session = AsyncMock()
        self.mock_session.add = MagicMock()

        # Standard synthetic Google UserInfo payload matching your router's extraction
        self.mock_google_user = {
            "email": "admin@todapay.com",
            "name": "System Admin",
            "picture": "https://lh3.googleusercontent.com/a/fake",
        }

    @patch("src.domain.users.router.get_oauth")
    async def test_login_redirects_to_google(self, mock_get_oauth: MagicMock) -> None:
        """Verifies the /login endpoint constructs the correct OAuth2 redirect flow."""
        mock_oauth = MagicMock()
        mock_oauth.google.authorize_redirect = AsyncMock(
            return_value=RedirectResponse(url="https://accounts.google.com/o/oauth2/v2/auth")
        )
        mock_get_oauth.return_value = mock_oauth

        response = await login(self.mock_request)

        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers["location"], "https://accounts.google.com/o/oauth2/v2/auth")
        mock_oauth.google.authorize_redirect.assert_awaited_once_with(
            self.mock_request, "https://gateway.local/auth/google"
        )

    @patch("src.domain.users.router.settings")
    @patch("src.domain.users.router.get_oauth")
    async def test_auth_google_jit_provisioning_new_admin(
        self, mock_get_oauth: MagicMock, mock_settings: MagicMock
    ) -> None:
        """Verifies a first-time SSO login creates an active Admin if matching settings."""
        mock_settings.INITIAL_ADMIN_EMAIL = "admin@todapay.com"

        mock_oauth = MagicMock()
        mock_oauth.google.authorize_access_token = AsyncMock(return_value={"userinfo": self.mock_google_user})
        mock_get_oauth.return_value = mock_oauth

        # Simulate DB returning None (user does not exist)
        mock_db_result = MagicMock()
        mock_db_result.first.return_value = None
        self.mock_session.exec.return_value = mock_db_result

        response = await auth_google(self.mock_request, self.mock_session)

        # Verify DB Insert
        self.mock_session.add.assert_called_once()
        added_user = self.mock_session.add.call_args[0][0]
        self.assertIsInstance(added_user, User)
        self.assertEqual(added_user.email, "admin@todapay.com")
        self.assertEqual(added_user.role, UserRole.SYSTEM_ADMIN)
        self.assertTrue(added_user.is_active)

        # Verify Session Injection
        self.assertEqual(self.mock_request.session["user"]["email"], "admin@todapay.com")
        self.assertEqual(self.mock_request.session["user"]["role"], UserRole.SYSTEM_ADMIN.value)

        # Verify Redirect to Dashboard
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers["location"], "/")

    @patch("src.domain.users.router.settings")
    @patch("src.domain.users.router.get_oauth")
    async def test_auth_google_inactive_user_rejected(
        self, mock_get_oauth: MagicMock, mock_settings: MagicMock
    ) -> None:
        """Verifies that non-whitelisted new users are created but rejected with a 403."""
        mock_settings.INITIAL_ADMIN_EMAIL = "someone_else@todapay.com"

        mock_oauth = MagicMock()
        mock_oauth.google.authorize_access_token = AsyncMock(return_value={"userinfo": self.mock_google_user})
        mock_get_oauth.return_value = mock_oauth

        mock_db_result = MagicMock()
        mock_db_result.first.return_value = None
        self.mock_session.exec.return_value = mock_db_result

        with self.assertRaises(HTTPException) as context:
            await auth_google(self.mock_request, self.mock_session)

        self.assertEqual(context.exception.status_code, 403)
        self.assertIn("pending administrator approval", context.exception.detail)

    @patch("src.domain.users.router.settings")
    @patch("src.domain.users.router.get_oauth")
    async def test_auth_google_existing_user_sync(self, mock_get_oauth: MagicMock, mock_settings: MagicMock) -> None:
        """Verifies an existing user skips creation but updates dynamic fields (e.g., avatar)."""
        mock_oauth = MagicMock()
        mock_oauth.google.authorize_access_token = AsyncMock(return_value={"userinfo": self.mock_google_user})
        mock_get_oauth.return_value = mock_oauth

        # Simulate DB returning an existing User with an outdated name/avatar
        existing_user = User(
            id=1,
            email="admin@todapay.com",
            full_name="Unknown",
            avatar_url="old_pic",
            role=UserRole.SYSTEM_ADMIN,
            is_active=True,
        )
        mock_db_result = MagicMock()
        mock_db_result.first.return_value = existing_user
        self.mock_session.exec.return_value = mock_db_result

        await auth_google(self.mock_request, self.mock_session)

        # Verify DB skips Insert but commits updates
        self.mock_session.add.assert_called_once_with(existing_user)
        self.assertEqual(existing_user.full_name, "System Admin")
        self.assertEqual(existing_user.avatar_url, "https://lh3.googleusercontent.com/a/fake")
        self.mock_session.commit.assert_awaited_once()

    @patch("src.domain.users.router.get_oauth")
    async def test_auth_google_missing_userinfo_rejection(self, mock_get_oauth: MagicMock) -> None:
        """Verifies the callback aggressively rejects payloads missing the userinfo dictionary."""
        mock_oauth = MagicMock()
        # Payload missing the 'userinfo' key entirely
        mock_oauth.google.authorize_access_token = AsyncMock(return_value={"access_token": "123"})
        mock_get_oauth.return_value = mock_oauth

        with self.assertRaises(HTTPException) as context:
            await auth_google(self.mock_request, self.mock_session)

        self.assertEqual(context.exception.status_code, 400)
        self.assertIn("No user info received", context.exception.detail)

    async def test_logout_purges_session(self) -> None:
        """Verifies the /logout endpoint strictly annihilates the session dictionary."""
        self.mock_request.session = {"user": {"email": "admin@todapay.com"}}

        response = await logout(self.mock_request)

        self.assertEqual(self.mock_request.session, {})
        self.assertIsInstance(response, RedirectResponse)
        self.assertEqual(response.headers["location"], "/")


if __name__ == "__main__":
    unittest.main()
