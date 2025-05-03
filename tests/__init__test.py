import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from mcpauth import MCPAuth, MCPAuthAuthServerException, AuthServerExceptionCode
from mcpauth.config import AuthServerConfig, AuthServerType, AuthorizationServerMetadata
from mcpauth.types import AuthInfo


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

        # Exercise
        auth = MCPAuth(server=server_config)

        # Verify
        assert auth.server == server_config

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

        # Exercise & Verify
        with pytest.raises(MCPAuthAuthServerException) as exc_info:
            MCPAuth(server=server_config)

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

        # Exercise
        MCPAuth(server=server_config)

        # Verify
        assert mock_warning.called


@pytest.mark.asyncio
class TestOAuthMetadataEndpointAndRoute:
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

    async def test_metadata_endpoint(self):
        auth = MCPAuth(server=self.server_config)

        options_request = MagicMock()
        options_request.method = "OPTIONS"
        options_response = await auth.metadata_endpoint()(options_request)
        assert options_response.status_code == 204
        assert options_response.headers["Access-Control-Allow-Origin"] == "*"
        assert (
            options_response.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"
        )

        request = MagicMock()
        request.method = "GET"
        response = await auth.metadata_endpoint()(request)

        assert response.status_code == 200
        assert response.body == self.server_config.metadata.model_dump_json(
            exclude_none=True
        ).encode("utf-8")
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert response.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"

    async def test_metadata_route(self):
        auth = MCPAuth(server=self.server_config)
        route = auth.metadata_route()

        assert route.path == "/.well-known/oauth-authorization-server"
        assert route.methods == {"GET", "HEAD", "OPTIONS"}

        # Mock a request to the route
        request = MagicMock()
        request.method = "GET"
        response = await route.endpoint(request)
        assert response.status_code == 200
        assert response.body == self.server_config.metadata.model_dump_json(
            exclude_none=True
        ).encode("utf-8")
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        assert response.headers["Access-Control-Allow-Methods"] == "GET, OPTIONS"


class TestBearerAuthMiddleware:
    def test_bearer_auth_middleware_jwt_mode(self):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                jwks_uri="https://example.com/.well-known/jwks.json",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
            ),
        )
        auth = MCPAuth(server=server_config)

        # Exercise
        with patch("mcpauth.utils.create_verify_jwt") as mock_create_verify_jwt:
            mock_create_verify_jwt.return_value = MagicMock()
            middleware_class = auth.bearer_auth_middleware(
                "jwt", required_scopes=["profile"]
            )

        # Verify
        assert middleware_class is not None
        mock_create_verify_jwt.assert_called_once_with(
            "https://example.com/.well-known/jwks.json", leeway=60
        )

    @pytest.mark.asyncio
    async def test_bearer_auth_middleware_custom_verify(self):
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
        auth = MCPAuth(server=server_config)

        auth_info = AuthInfo(
            token="valid_token",
            issuer="https://example.com",
            subject="1234567890",
            scopes=["profile"],
            claims={},
        )
        custom_verify = MagicMock()
        custom_verify.return_value = auth_info

        middleware_class = auth.bearer_auth_middleware(
            custom_verify, required_scopes=["profile"]
        )

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": "Bearer valid_token"}
        middleware_instance = middleware_class(MagicMock())
        await middleware_instance.dispatch(mock_request, AsyncMock())
        assert auth.auth_info == auth_info

    def test_bearer_auth_middleware_jwt_without_jwks_uri(self):
        # Setup
        server_config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                # No jwks_uri
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
            ),
        )
        auth = MCPAuth(server=server_config)

        # Exercise & Verify
        with pytest.raises(MCPAuthAuthServerException) as exc_info:
            auth.bearer_auth_middleware("jwt", required_scopes=["profile"])

        assert exc_info.value.code == AuthServerExceptionCode.MISSING_JWKS_URI

    def test_bearer_auth_middleware_invalid_mode(self):
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
        auth = MCPAuth(server=server_config)

        # Exercise & Verify
        with pytest.raises(ValueError) as exc_info:
            auth.bearer_auth_middleware(
                "invalid_mode",  # type: ignore
                required_scopes=["profile"],
            )

        assert "mode_or_verify must be 'jwt' or a callable function" in str(
            exc_info.value
        )
