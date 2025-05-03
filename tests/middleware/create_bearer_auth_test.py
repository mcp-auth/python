from contextvars import ContextVar
import json
import pytest
from unittest.mock import MagicMock, AsyncMock
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from mcpauth.types import AuthInfo, VerifyAccessTokenFunction

from mcpauth.middleware.create_bearer_auth import (
    create_bearer_auth,
    BearerAuthConfig,
    BearerAuthExceptionCode,
)
from mcpauth.exceptions import (
    AuthServerExceptionCode,
    MCPAuthTokenVerificationException,
    MCPAuthAuthServerException,
    MCPAuthConfigException,
    MCPAuthTokenVerificationExceptionCode,
)


class TestHandleBearerAuth:
    def test_should_return_middleware_class(self):
        middleware = create_bearer_auth(
            lambda _: None,  # type: ignore
            BearerAuthConfig(issuer="https://example.com"),
            ContextVar("auth_info", default=None),
        )
        assert callable(middleware)

    def test_should_throw_error_if_verify_access_token_is_not_a_function(self):
        with pytest.raises(
            TypeError, match=r"`verify_access_token` must be a function"
        ):
            create_bearer_auth(
                "not a function",  # type: ignore
                BearerAuthConfig(issuer="https://example.com"),
                ContextVar("auth_info", default=None),
            )

    def test_should_throw_error_if_issuer_is_not_a_valid_url(self):
        with pytest.raises(TypeError, match=r"`issuer` must be a valid URL."):
            create_bearer_auth(
                lambda _: None,  # type: ignore
                BearerAuthConfig(issuer="not a valid url"),
                ContextVar("auth_info", default=None),
            )


@pytest.mark.asyncio
class TestHandleBearerAuthMiddleware:
    @pytest.fixture
    def auth_info_context(self):
        return ContextVar("auth_info", default=None)

    @pytest.fixture
    def auth_config(self, auth_info_context: ContextVar[AuthInfo | None]):
        issuer = "https://example.com"
        required_scopes = ["read", "write"]
        audience = "test-audience"

        def verify_access_token(token: str) -> AuthInfo:
            if token == "valid-token":
                return AuthInfo(
                    issuer=issuer,
                    client_id="client-id",
                    scopes=["read", "write"],
                    token=token,
                    audience=audience,
                    subject="subject-id",
                    claims={"sub": "subject-id", "aud": audience, "iss": issuer},
                )
            raise MCPAuthTokenVerificationException(
                MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
            )

        return (
            verify_access_token,
            BearerAuthConfig(
                issuer=issuer,
                required_scopes=required_scopes,
                audience=audience,
            ),
            auth_info_context,
        )

    @pytest.fixture
    def middleware(
        self,
        auth_config: tuple[
            VerifyAccessTokenFunction, BearerAuthConfig, ContextVar[AuthInfo | None]
        ],
    ):
        MiddlewareClass = create_bearer_auth(
            auth_config[0], auth_config[1], auth_config[2]
        )
        return MiddlewareClass(app=MagicMock())

    async def test_should_respond_with_error_if_request_does_not_have_bearer_token(
        self, middleware: BaseHTTPMiddleware
    ):
        # Create mock request with no Authorization header
        request = Request(
            scope={
                "type": "http",
                "headers": [],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 401
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": BearerAuthExceptionCode.MISSING_AUTH_HEADER.value,
            "error_description": "Missing `Authorization` header. Please provide a valid bearer token.",
        }

    async def test_should_respond_with_error_if_bearer_token_is_malformed(
        self, middleware: BaseHTTPMiddleware
    ):
        # Test case 1: Invalid token format
        request1 = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer invalid token format")],
                "method": "GET",
                "path": "/",
            }
        )

        response1 = await middleware.dispatch(request1, MagicMock())

        assert response1.status_code == 401
        assert isinstance(response1, JSONResponse) and isinstance(response1.body, bytes)
        response1_data = json.loads(response1.body.decode("utf-8"))
        assert response1_data == {
            "error": BearerAuthExceptionCode.INVALID_AUTH_HEADER_FORMAT.value,
            "error_description": 'Invalid `Authorization` header format. Expected "Bearer <token>".',
        }

        # Test case 2: Invalid header format
        request2 = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"invalid-header")],
                "method": "GET",
                "path": "/",
            }
        )

        response2 = await middleware.dispatch(request2, MagicMock())

        assert response2.status_code == 401
        assert isinstance(response2, JSONResponse) and isinstance(response2.body, bytes)
        response2_data = json.loads(response2.body.decode("utf-8"))
        assert response2_data == {
            "error": BearerAuthExceptionCode.INVALID_AUTH_HEADER_FORMAT.value,
            "error_description": 'Invalid `Authorization` header format. Expected "Bearer <token>".',
        }

        # Test case 3: Missing token
        request3 = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer ")],
                "method": "GET",
                "path": "/",
            }
        )

        response3 = await middleware.dispatch(request3, MagicMock())

        assert response3.status_code == 401
        assert isinstance(response3, JSONResponse) and isinstance(response3.body, bytes)
        response3_data = json.loads(response3.body.decode("utf-8"))
        assert response3_data == {
            "error": BearerAuthExceptionCode.MISSING_BEARER_TOKEN.value,
            "error_description": "Missing bearer token in `Authorization` header. Please provide a valid token.",
        }

    async def test_should_respond_with_error_if_bearer_token_is_not_valid(
        self,
        auth_config: tuple[
            VerifyAccessTokenFunction, BearerAuthConfig, ContextVar[AuthInfo | None]
        ],
    ):
        mock_verify = MagicMock(
            side_effect=MCPAuthTokenVerificationException(
                MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
            )
        )
        MiddlewareClass = create_bearer_auth(
            mock_verify, auth_config[1], auth_config[2]
        )
        middleware = MiddlewareClass(app=MagicMock())

        mock_verify.side_effect = MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
        )

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer invalid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 401
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "invalid_token",
            "error_description": "The provided token is invalid or malformed.",
        }
        mock_verify.assert_called_once_with("invalid-token")

    async def test_should_respond_with_error_if_issuer_does_not_match(
        self,
        auth_config: tuple[
            VerifyAccessTokenFunction, BearerAuthConfig, ContextVar[AuthInfo | None]
        ],
    ):
        mock_verify = MagicMock()
        mock_verify.return_value = AuthInfo(
            issuer="https://wrong-issuer.com",
            client_id="client-id",
            scopes=["read", "write"],
            token="valid-token",
            audience=auth_config[1].audience,
            subject="subject-id",
            claims={
                "sub": "subject-id",
                "aud": auth_config[1].audience,
                "iss": "https://wrong-issuer.com",
            },
        )

        MiddlewareClass = create_bearer_auth(
            mock_verify, auth_config[1], auth_config[2]
        )
        middleware = MiddlewareClass(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 401
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "invalid_issuer",
            "error_description": "The token issuer does not match the expected issuer.",
        }
        mock_verify.assert_called_once_with("valid-token")

    async def test_should_respond_with_error_if_audience_does_not_match(
        self,
        auth_config: tuple[
            VerifyAccessTokenFunction, BearerAuthConfig, ContextVar[AuthInfo | None]
        ],
    ):
        mock_verify = MagicMock()
        mock_verify.return_value = AuthInfo(
            issuer=auth_config[1].issuer,
            client_id="client-id",
            scopes=["read", "write"],
            token="valid-token",
            audience="wrong-audience",
            subject="subject-id",
            claims={
                "sub": "subject-id",
                "aud": "wrong-audience",
                "iss": auth_config[1].issuer,
            },
        )

        MiddlewareClass = create_bearer_auth(
            mock_verify, auth_config[1], auth_config[2]
        )
        middleware = MiddlewareClass(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 401
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "invalid_audience",
            "error_description": "The token audience does not match the expected audience.",
        }
        mock_verify.assert_called_once_with("valid-token")

    async def test_should_respond_with_error_if_audience_does_not_match_array_case(
        self,
        auth_config: tuple[
            VerifyAccessTokenFunction, BearerAuthConfig, ContextVar[AuthInfo | None]
        ],
    ):
        mock_verify = MagicMock()
        mock_verify.return_value = AuthInfo(
            issuer=auth_config[1].issuer,
            client_id="client-id",
            scopes=["read", "write"],
            token="valid-token",
            audience=["wrong-audience"],
            subject="subject-id",
            claims={
                "sub": "subject-id",
                "aud": ["wrong-audience"],
                "iss": auth_config[1].issuer,
            },
        )

        MiddlewareClass = create_bearer_auth(
            mock_verify, auth_config[1], auth_config[2]
        )
        middleware = MiddlewareClass(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 401
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "invalid_audience",
            "error_description": "The token audience does not match the expected audience.",
        }
        mock_verify.assert_called_once_with("valid-token")

    async def test_should_respond_with_error_if_required_scopes_are_not_present(
        self,
        auth_config: tuple[
            VerifyAccessTokenFunction, BearerAuthConfig, ContextVar[AuthInfo | None]
        ],
    ):
        mock_verify = MagicMock()
        mock_verify.return_value = AuthInfo(
            issuer=auth_config[1].issuer,
            client_id="client-id",
            scopes=["read"],  # Missing "write" scope
            token="valid-token",
            audience=auth_config[1].audience,
            subject="subject-id",
            claims={
                "sub": "subject-id",
                "aud": auth_config[1].audience,
                "iss": auth_config[1].issuer,
            },
        )

        MiddlewareClass = create_bearer_auth(
            mock_verify, auth_config[1], auth_config[2]
        )
        middleware = MiddlewareClass(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 403
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "missing_required_scopes",
            "error_description": "The token does not contain the necessary scopes for this request.",
            "missing_scopes": ["write"],
        }
        mock_verify.assert_called_once_with("valid-token")

    async def test_should_call_next_if_token_is_valid_and_has_correct_audience_and_scopes(
        self, middleware: BaseHTTPMiddleware
    ):
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        next_call = AsyncMock()
        next_call.return_value = Response(status_code=200)

        response = await middleware.dispatch(request, next_call)

        # Verify next was called
        next_call.assert_called_once()
        assert response.status_code == 200

    async def test_should_override_existing_auth_property_on_request(
        self,
        middleware: BaseHTTPMiddleware,
        auth_info_context: ContextVar[AuthInfo | None],
    ):
        # Create request with existing auth attribute
        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        auth_info_context.set(
            AuthInfo(
                token="old-valid-token",
                subject="old-subject-id",
                issuer="https://old-issuer.com",
                client_id="old-client-id",
                scopes=["old-scope"],
                claims={},
            )
        )

        # Create mock for next_call
        next_call = AsyncMock()
        next_call.return_value = Response(status_code=200)

        response = await middleware.dispatch(request, next_call)
        current_auth_info = auth_info_context.get()

        assert current_auth_info is not None
        assert current_auth_info.issuer == "https://example.com"
        assert current_auth_info.client_id == "client-id"
        assert current_auth_info.scopes == ["read", "write"]
        assert current_auth_info.token == "valid-token"
        assert current_auth_info.audience == "test-audience"
        assert current_auth_info.subject == "subject-id"

        next_call.assert_called_once()
        assert response.status_code == 200

    async def test_should_handle_mcp_auth_server_error_and_config_error(self):
        # Test MCPAuthAuthServerError with show_error_details enabled
        mock_verify = MagicMock()
        mock_verify.side_effect = MCPAuthAuthServerException(
            AuthServerExceptionCode.INVALID_SERVER_CONFIG,
            cause=Exception("Server configuration is invalid"),
        )

        config = BearerAuthConfig(
            issuer="https://example.com",
            required_scopes=[],
            audience=None,
            show_error_details=True,
        )

        MiddlewareClass = create_bearer_auth(
            mock_verify, config, ContextVar("auth_info", default=None)
        )
        middleware = MiddlewareClass(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 500
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "server_error",
            "error_description": "An error occurred with the authorization server.",
            "cause": {
                "error": "invalid_server_config",
                "error_description": "The server configuration does not match the MCP specification.",
            },
        }

        # Test MCPAuthConfigException
        mock_verify_config = MagicMock()
        mock_verify_config.side_effect = MCPAuthConfigException(
            "invalid_config", "Configuration is invalid"
        )

        config_error_middleware_class = create_bearer_auth(
            mock_verify_config,
            BearerAuthConfig(
                issuer="https://example.com", required_scopes=[], audience=None
            ),
            ContextVar("auth_info", default=None),
        )
        config_error_middleware = config_error_middleware_class(app=MagicMock())

        config_error_request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        config_error_response = await config_error_middleware.dispatch(
            config_error_request, MagicMock()
        )

        assert config_error_response.status_code == 500
        assert isinstance(config_error_response, JSONResponse) and isinstance(
            config_error_response.body, bytes
        )
        config_error_response_data = json.loads(
            config_error_response.body.decode("utf-8")
        )
        assert config_error_response_data == {
            "error": "server_error",
            "error_description": "An error occurred with the authorization server.",
        }

    async def test_should_throw_for_unexpected_errors(self):
        mock_verify = MagicMock()
        mock_verify.side_effect = Exception("Unexpected error")

        middleware_class = create_bearer_auth(
            mock_verify,
            BearerAuthConfig(
                issuer="https://example.com", required_scopes=[], audience=None
            ),
            ContextVar("auth_info", default=None),
        )
        middleware = middleware_class(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        with pytest.raises(Exception, match="Unexpected error"):
            await middleware.dispatch(request, MagicMock())

    async def test_should_show_error_details_for_bearer_auth_error(self):
        issuer = "https://example.com"
        required_scopes = ["read", "write"]
        audience = "test-audience"

        mock_verify = MagicMock()
        mock_verify.return_value = AuthInfo(
            issuer=issuer + "1",  # Different issuer
            client_id="client-id",
            scopes=required_scopes,
            token="valid-token",
            audience=audience,
            subject="subject-id",
            claims={"sub": "subject-id", "aud": audience, "iss": issuer + "1"},
        )

        middleware_class = create_bearer_auth(
            mock_verify,
            BearerAuthConfig(
                issuer=issuer,
                required_scopes=required_scopes,
                audience=audience,
                show_error_details=True,
            ),
            ContextVar("auth_info", default=None),
        )
        middleware = middleware_class(app=MagicMock())

        request = Request(
            scope={
                "type": "http",
                "headers": [(b"authorization", b"Bearer valid-token")],
                "method": "GET",
                "path": "/",
            }
        )

        response = await middleware.dispatch(request, MagicMock())

        assert response.status_code == 401
        assert isinstance(response, JSONResponse) and isinstance(response.body, bytes)
        response_data = json.loads(response.body.decode("utf-8"))
        assert response_data == {
            "error": "invalid_issuer",
            "error_description": "The token issuer does not match the expected issuer.",
            "cause": {
                "expected": issuer,
                "actual": issuer + "1",
            },
        }
        mock_verify.assert_called_once_with("valid-token")
