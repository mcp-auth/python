import pytest
from unittest.mock import patch, MagicMock
from mcpauth import MCPAuth, MCPAuthAuthServerException, AuthServerExceptionCode
from mcpauth.config import AuthServerConfig, AuthServerType, AuthorizationServerMetadata


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


class TestOAuthMetadataResponse:
    def test_metadata_response(self):
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

        # Exercise
        response = auth.metadata_response()

        # Verify
        assert response.status_code == 200
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

    def test_bearer_auth_middleware_custom_verify(self):
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

        custom_verify = MagicMock()

        # Exercise
        with patch(
            "mcpauth.middleware.create_bearer_auth.create_bearer_auth"
        ) as mock_create_bearer_auth:
            middleware_class = auth.bearer_auth_middleware(
                custom_verify, required_scopes=["profile"]
            )

        # Verify
        assert middleware_class is not None
        mock_create_bearer_auth.assert_called_once()
        args, kwargs = mock_create_bearer_auth.call_args
        assert args[0] == custom_verify
        assert kwargs == {}

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
