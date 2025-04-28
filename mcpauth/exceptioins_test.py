from enum import Enum
from mcpauth.exceptions import (
    AuthServerExceptionCode,
    BearerAuthExceptionCode,
    MCPAuthAuthServerException,
    MCPAuthBearerAuthException,
    MCPAuthBearerAuthExceptionDetails,
    MCPAuthException,
    MCPAuthJwtVerificationException,
    MCPAuthJwtVerificationExceptionCode,
)


class WrongExceptionCode(str, Enum):
    unknown = "unknown_code"


class TestMCPAuthException:
    def test_to_json(self):
        exception = Exception("Test exception")
        mcp_exception = MCPAuthException("test_code", "Test message", cause=exception)

        assert mcp_exception.to_json() == {
            "error": "test_code",
            "error_description": "Test message",
        }

        assert mcp_exception.to_json(show_cause=True) == {
            "error": "test_code",
            "error_description": "Test message",
            "cause": exception,
        }

    def test_properties(self):
        mcp_exception = MCPAuthException("test_code", "Test message")
        assert mcp_exception.code == "test_code"


class TestMCPAuthAuthServerException:
    def test_message_based_on_code(self):
        mcp_exception = MCPAuthAuthServerException(
            AuthServerExceptionCode.INVALID_SERVER_METADATA
        )
        assert mcp_exception.message == "The server metadata is invalid or malformed."
        assert mcp_exception.to_json() == {
            "error": "invalid_server_metadata",
            "error_description": "The server metadata is invalid or malformed.",
        }

    def test_default_message_for_unknown_code(self):
        mcp_exception = MCPAuthAuthServerException(WrongExceptionCode.unknown)  # type: ignore
        assert (
            mcp_exception.message
            == "An exception occurred with the authorization server."
        )
        assert mcp_exception.to_json() == {
            "error": "unknown_code",
            "error_description": "An exception occurred with the authorization server.",
        }


class TestMCPAuthBearerAuthException:
    def test_message_based_on_code(self):
        mcp_exception = MCPAuthBearerAuthException(
            BearerAuthExceptionCode.MISSING_AUTH_HEADER
        )
        assert mcp_exception.message == (
            "Missing `Authorization` header. Please provide a valid bearer token."
        )
        assert mcp_exception.to_json() == {
            "error": "missing_auth_header",
            "error_description": "Missing `Authorization` header. Please provide a valid bearer token.",
        }

    def test_default_message_for_unknown_code(self):
        mcp_exception = MCPAuthBearerAuthException(WrongExceptionCode.unknown)  # type: ignore
        assert mcp_exception.message == "An exception occurred with the Bearer auth."
        assert mcp_exception.to_json() == {
            "error": "unknown_code",
            "error_description": "An exception occurred with the Bearer auth.",
        }

    def test_error_uri_and_missing_scopes_in_json(self):
        uri = "https://example.com/error"
        mcp_exception = MCPAuthBearerAuthException(
            BearerAuthExceptionCode.MISSING_REQUIRED_SCOPES,
            cause=MCPAuthBearerAuthExceptionDetails(
                missing_scopes=["scope1", "scope2"], uri=uri
            ),
        )
        result = mcp_exception.to_json()
        assert result["error"] == "missing_required_scopes"
        assert result["error_uri"] == uri
        assert result["missing_scopes"] == ["scope1", "scope2"]


class TestMCPAuthJwtVerificationException:
    def test_message_based_on_code(self):
        mcp_exception = MCPAuthJwtVerificationException(
            MCPAuthJwtVerificationExceptionCode.INVALID_JWT
        )
        assert mcp_exception.message == "The provided JWT is invalid or malformed."
        assert mcp_exception.to_json() == {
            "error": "invalid_jwt",
            "error_description": "The provided JWT is invalid or malformed.",
        }

    def test_default_message_for_unknown_code(self):
        mcp_exception = MCPAuthJwtVerificationException(WrongExceptionCode.unknown)  # type: ignore
        assert mcp_exception.message == "An exception occurred while verifying the JWT."
        assert mcp_exception.to_json() == {
            "error": "unknown_code",
            "error_description": "An exception occurred while verifying the JWT.",
        }
