import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from starlette.requests import Request
from starlette.responses import Response
from mcpauth import MCPAuth, MCPAuthAuthServerException, AuthServerExceptionCode
from mcpauth.config import MCPAuthConfig
from mcpauth.models.auth_server import AuthServerConfig, AuthServerType
from mcpauth.models.oauth import AuthorizationServerMetadata


class TestMCPAuth:
    def test_init_with_valid_config(self):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
            ),
        )
        config = MCPAuthConfig(server=server_config)

        # Exercise
        auth = MCPAuth(config)

        # Verify
        assert auth.config == config

    def test_init_with_invalid_config(self):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["token"],  # Invalid response type
            ),
        )
        config = MCPAuthConfig(server=server_config)

        # Exercise & Verify
        with pytest.raises(MCPAuthAuthServerException) as exc_info:
            MCPAuth(config)

        assert exc_info.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG

    @patch("mcpauth.logging.warning")
    def test_init_with_warnings(self, mock_warning: MagicMock):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
                # Missing registration_endpoint will cause a warning
            ),
        )
        config = MCPAuthConfig(server=server_config)

        # Exercise
        MCPAuth(config)

        # Verify
        assert mock_warning.called

    @pytest.mark.asyncio
    async def test_delegated_middleware_oauth_endpoint(self):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
            ),
        )
        config = MCPAuthConfig(server=server_config)
        auth = MCPAuth(config)

        middleware_class = auth.delegated_middleware()
        middleware = middleware_class(app=MagicMock())

        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/.well-known/oauth-authorization-server"

        # Exercise
        response = await middleware.dispatch(mock_request, call_next=AsyncMock())

        # Verify
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert response.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"

    @pytest.mark.asyncio
    async def test_delegated_middleware_other_endpoint(self):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
            ),
        )
        config = MCPAuthConfig(server=server_config)
        auth = MCPAuth(config)

        middleware_class = auth.delegated_middleware()
        middleware = middleware_class(app=MagicMock())

        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/some-other-path"

        mock_response = Response(content="Test response")
        mock_call_next = AsyncMock(return_value=mock_response)

        # Exercise
        response = await middleware.dispatch(mock_request, call_next=mock_call_next)

        # Verify
        assert mock_call_next.called
        assert response == mock_response
