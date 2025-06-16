import pytest
from unittest.mock import patch, MagicMock
from starlette.routing import Route

from mcpauth import MCPAuth, MCPAuthAuthServerException, AuthServerExceptionCode
from mcpauth.config import AuthServerConfig, AuthServerType, AuthorizationServerMetadata
from mcpauth.types import ResourceServerConfig, ResourceServerMetadata


@pytest.fixture
def valid_server_config() -> AuthServerConfig:
    """Fixture for a valid authorization server configuration."""
    return AuthServerConfig(
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


@pytest.fixture
def valid_resource_config() -> ResourceServerConfig:
    """Fixture for a valid resource server configuration."""
    return ResourceServerConfig(
        metadata=ResourceServerMetadata(
            resource="https://api.example.com",
            authorization_servers=[
                AuthServerConfig(
                    type=AuthServerType.OAUTH,
                    metadata=AuthorizationServerMetadata(
                        issuer="https://example.com",
                        authorization_endpoint="https://example.com/oauth/authorize",
                        token_endpoint="https://example.com/oauth/token",
                        response_types_supported=["code"],
                    ),
                )
            ],
        )
    )

def test_init_throws_if_no_config():
    """Test that MCPAuth throws an error if no configuration is provided."""
    with pytest.raises(MCPAuthAuthServerException) as exc_info:
        MCPAuth()
    assert exc_info.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


def test_init_throws_if_both_configs_provided(
    valid_server_config: AuthServerConfig, valid_resource_config: ResourceServerConfig
):
    """Test that MCPAuth throws an error if both server and resource configs are provided."""
    with pytest.raises(MCPAuthAuthServerException) as exc_info:
        MCPAuth(server=valid_server_config, protected_resources=valid_resource_config)
    assert exc_info.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch("mcpauth.AuthorizationServerHandler")
def test_init_instantiates_auth_server_handler(
    mock_auth_handler: MagicMock, valid_server_config: AuthServerConfig
):
    """Test that MCPAuth instantiates AuthorizationServerHandler when server config is provided."""
    MCPAuth(server=valid_server_config)
    mock_auth_handler.assert_called_once()


@patch("mcpauth.ResourceServerHandler")
def test_init_instantiates_resource_server_handler(
    mock_resource_handler: MagicMock, valid_resource_config: ResourceServerConfig
):
    """Test that MCPAuth instantiates ResourceServerHandler when resource config is provided."""
    MCPAuth(protected_resources=valid_resource_config)
    mock_resource_handler.assert_called_once()


def test_bearer_auth_middleware_throws_if_resource_missing_in_resource_mode(
    valid_resource_config: ResourceServerConfig,
):
    """Test that bearer_auth_middleware throws an error if resource is not specified in resource server mode."""
    # We need to mock the handler to be a ResourceServerHandler instance
    auth = MCPAuth(protected_resources=valid_resource_config)
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        auth.bearer_auth_middleware(mode_or_verify="jwt")
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


def test_bearer_auth_middleware_calls_get_token_verifier_in_auth_server_mode(
    valid_server_config: AuthServerConfig,
):
    """Test that bearer_auth_middleware calls get_token_verifier on its handler."""
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate:
        mock_validate.return_value.is_valid = True
        auth = MCPAuth(server=valid_server_config)
        # Spy on the handler's method
        with patch.object(
            auth._handler, "get_token_verifier", return_value=MagicMock()  # type: ignore[reportPrivateUsage]
        ) as mock_get_verifier:
            auth.bearer_auth_middleware(mode_or_verify="jwt")
            mock_get_verifier.assert_called_once_with(resource="")


def test_bearer_auth_middleware_calls_get_token_verifier_in_resource_mode(
    valid_resource_config: ResourceServerConfig,
):
    """Test that bearer_auth_middleware calls get_token_verifier on its handler."""
    with patch(
        "mcpauth.auth.resource_server_handler.validate_server_config"
    ) as mock_validate:
        mock_validate.return_value.is_valid = True
        auth = MCPAuth(protected_resources=valid_resource_config)
        # Spy on the handler's method
        with patch.object(
            auth._handler, "get_token_verifier", return_value=MagicMock()  # type: ignore[reportPrivateUsage]
        ) as mock_get_verifier:
            auth.bearer_auth_middleware(
                mode_or_verify="jwt", resource="https://api.example.com"
            )
            mock_get_verifier.assert_called_once_with(resource="https://api.example.com")


@patch("mcpauth.auth.resource_server_handler.validate_server_config")
def test_metadata_route_throws_in_resource_mode(
    mock_validate: MagicMock, valid_resource_config: ResourceServerConfig
):
    """Test that metadata_route throws an error in resource server mode."""
    auth = MCPAuth(protected_resources=valid_resource_config)
    with pytest.raises(MCPAuthAuthServerException):
        with pytest.warns(DeprecationWarning):
            auth.metadata_route() # pyright: ignore[reportDeprecated]


@patch("mcpauth.auth.authorization_server_handler.validate_server_config")
def test_resource_metadata_router_throws_in_auth_server_mode(
    mock_validate: MagicMock, valid_server_config: AuthServerConfig
):
    """Test that resource_metadata_router throws an error in authorization server mode."""
    auth = MCPAuth(server=valid_server_config)
    with pytest.raises(MCPAuthAuthServerException):
        auth.resource_metadata_router()


@patch(
    "mcpauth.auth.authorization_server_handler.AuthorizationServerHandler.create_metadata_route"
)
@patch("mcpauth.auth.authorization_server_handler.validate_server_config")
def test_metadata_route_calls_handler_method(
    mock_validate: MagicMock,
    mock_create_route: MagicMock,
    valid_server_config: AuthServerConfig,
):
    """Test that metadata_route calls the handler's create_metadata_route method."""
    # Ensure the mock returns a router-like object with a routes attribute
    mock_route_instance = MagicMock(spec=Route)
    mock_create_route.return_value = MagicMock(routes=[mock_route_instance])
    auth = MCPAuth(server=valid_server_config)
    with pytest.warns(DeprecationWarning):
        auth.metadata_route() # pyright: ignore[reportDeprecated]
    mock_create_route.assert_called_once()


@patch(
    "mcpauth.auth.resource_server_handler.ResourceServerHandler.create_metadata_route"
)
@patch("mcpauth.auth.resource_server_handler.validate_server_config")
def test_resource_metadata_router_calls_handler_method(
    mock_validate: MagicMock,
    mock_create_route: MagicMock,
    valid_resource_config: ResourceServerConfig,
):
    """Test that resource_metadata_router calls the handler's create_metadata_route method."""
    auth = MCPAuth(protected_resources=valid_resource_config)
    auth.resource_metadata_router()
    mock_create_route.assert_called_once() 