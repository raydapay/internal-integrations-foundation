import json
import unittest
from unittest.mock import MagicMock, patch

from src.core.logger import SeqSink, _sanitize_value, log_patcher


class DummyConnection:
    """A minimal dummy class that relies on default object.__repr__ (containing 'at 0x...')."""

    pass


async def dummy_coroutine() -> None:
    pass


class TestLoggerSanitization(unittest.TestCase):
    """Test suite for Loguru payload beautification and sanitization constraints."""

    def test_sanitize_value_primitives_and_collections(self) -> None:
        """Verifies standard data structures are traversed and returned unmodified."""
        raw_data = {"key1": "val1", "key2": [1, 2, 3], "key3": {"nested": True}}
        sanitized = _sanitize_value(raw_data)

        self.assertEqual(sanitized, raw_data)
        self.assertIsInstance(sanitized["key2"], list)

    def test_sanitize_value_memory_addresses(self) -> None:
        """Verifies ugly default __repr__ memory addresses are stripped into clean module strings."""
        dummy = DummyConnection()
        raw_repr = repr(dummy)

        self.assertIn(" at 0x", raw_repr)
        self.assertIn("<", raw_repr)

        sanitized = _sanitize_value(dummy)
        expected_str = f"[{dummy.__class__.__module__}.DummyConnection]"

        self.assertEqual(sanitized, expected_str)

    def test_sanitize_value_callables_and_coroutines(self) -> None:
        """Verifies unbound methods and coroutines are safely stringified."""
        # Sanitize a standard function
        sanitized_func = _sanitize_value(log_patcher)
        self.assertEqual(sanitized_func, f"{log_patcher.__module__}.log_patcher()")

        # Sanitize an async coroutine
        sanitized_coro = _sanitize_value(dummy_coroutine)
        self.assertEqual(sanitized_coro, f"{dummy_coroutine.__module__}.dummy_coroutine()")

    def test_log_patcher_mutates_record(self) -> None:
        """Verifies the global patcher successfully intercepts and cleans Loguru context records."""
        dummy = DummyConnection()
        record = {"extra": {"db": dummy}, "args": (dummy, "string_arg")}

        log_patcher(record)

        expected_str = f"[{dummy.__class__.__module__}.DummyConnection]"
        self.assertEqual(record["extra"]["db"], expected_str)
        self.assertEqual(record["args"][0], expected_str)
        self.assertEqual(record["args"][1], "string_arg")


class TestSeqSink(unittest.TestCase):
    """Test suite for the synchronous HTTP sink routing JSON logs to Seq."""

    def setUp(self) -> None:
        self.sink = SeqSink("http://fake-seq:5341", api_key="secret123")

        # Construct a synthetic serialized Loguru record
        self.mock_loguru_json = json.dumps(
            {
                "record": {
                    "time": {"repr": "2026-02-27 15:00:00"},
                    "level": {"name": "ERROR"},
                    "message": "Test error occurred",
                    "extra": {"custom_tag": "test_tag"},
                    "function": "test_func",
                    "module": "test_mod",
                    "line": 42,
                    "process": {"name": "MainProcess"},
                    "exception": {"text": "Traceback string here"},
                }
            }
        )

    @patch("src.core.logger.httpx.Client.post")
    def test_seq_sink_write_success(self, mock_post: MagicMock) -> None:
        """Verifies valid mapping of the Loguru dictionary into the Seq JSON API format."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        self.sink.write(self.mock_loguru_json)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args

        self.assertEqual(args[0], "http://fake-seq:5341/api/events/raw")
        self.assertEqual(kwargs["headers"]["X-Seq-ApiKey"], "secret123")

        payload = kwargs["json"]["Events"][0]
        self.assertEqual(payload["Level"], "ERROR")
        self.assertEqual(payload["Properties"]["custom_tag"], "test_tag")
        self.assertEqual(payload["Properties"]["Process"], "MainProcess")
        self.assertEqual(payload["Exception"], "Traceback string here")

    @patch("src.core.logger.sys.stderr.write")
    @patch("src.core.logger.httpx.Client.post")
    def test_seq_sink_http_error_fallback(self, mock_post: MagicMock, mock_stderr_write: MagicMock) -> None:
        """Verifies that an upstream Seq rejection safely dumps to stderr instead of crashing the thread."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        self.sink.write(self.mock_loguru_json)

        mock_stderr_write.assert_called_once()
        self.assertIn("Seq API Error 401", mock_stderr_write.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
