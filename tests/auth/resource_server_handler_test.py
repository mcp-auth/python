import pytest
from unittest.mock import patch, Mock
from starlette.testclient import TestClient

from mcpauth.auth.resource_server_handler import (
    ResourceServerHandler,
    ResourceServerModeConfig,
)
from mcpauth.config import AuthServerConfig, AuthServerType, AuthorizationServerMetadata
from mcpauth.types import ResourceServerConfig as RSC, ResourceServerMetadata
from mcpauth.exceptions import MCPAuthAuthServerException, AuthServerExceptionCode
from mcpauth.utils import create_resource_metadata_endpoint


@pytest.fixture
def mock_auth_server() -> AuthServerConfig:
    return AuthServerConfig(
        metadata=AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/auth",
            token_endpoint="https://auth.example.com/token",
            response_types_supported=["code"],
        ),
        type=AuthServerType.OAUTH,
    )


@pytest.fixture
def mock_resource_config(mock_auth_server: AuthServerConfig) -> RSC:
    return RSC(
        metadata=ResourceServerMetadata(
            resource="https://my-api.com", authorization_servers=[mock_auth_server]
        )
    )


@patch("mcpauth.auth.resource_server_handler.TokenVerifier")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_single_resource(
    mock_validate: Mock,
    mock_token_verifier: Mock,
    mock_resource_config: RSC,
    mock_auth_server: AuthServerConfig,
):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    assert handler._resources_configs == [mock_resource_config] # type: ignore[reportProtectedUsage]
    mock_validate.assert_called_once_with(mock_auth_server)
    mock_token_verifier.assert_called_once_with([mock_auth_server])


@patch("mcpauth.auth.resource_server_handler.TokenVerifier")
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_multiple_resources(
    mock_validate: Mock,
    mock_token_verifier: Mock,
    mock_resource_config: RSC,
    mock_auth_server: AuthServerConfig,
):
    config2 = RSC(
        metadata=ResourceServerMetadata(
            resource="my-api-2", authorization_servers=[mock_auth_server]
        )
    )
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=[mock_resource_config, config2])
    )
    assert handler._resources_configs == [mock_resource_config, config2] # type: ignore[reportProtectedUsage]
    assert mock_validate.call_count == 2
    assert mock_token_verifier.call_count == 2


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_duplicate_resource_id(mock_validate: Mock, mock_resource_config: RSC):
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        ResourceServerHandler(
            ResourceServerModeConfig(
                protected_resources=[mock_resource_config, mock_resource_config]
            )
        )
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_init_duplicate_auth_server(
    mock_validate: Mock, mock_auth_server: AuthServerConfig
):
    """Test that ResourceServerHandler throws an error if an auth server is duplicated for a resource."""
    config_with_duplicate_auth_server = RSC(
        metadata=ResourceServerMetadata(
            resource="https://my-api.com",
            authorization_servers=[mock_auth_server, mock_auth_server],
        )
    )
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        ResourceServerHandler(
            ResourceServerModeConfig(
                protected_resources=[config_with_duplicate_auth_server]
            )
        )
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG
    assert (
        excinfo.value.cause["error_description"]  # type: ignore[reportGeneralTypeIssues]
        == "The authorization server ('https://auth.example.com') for resource 'https://my-api.com' is duplicated."
    )


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_get_token_verifier_success(mock_validate: Mock, mock_resource_config: RSC):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    verifier = handler.get_token_verifier("https://my-api.com")
    assert verifier is not None


@pytest.mark.parametrize("resource", [None, ""])
@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_get_token_verifier_no_resource(
    mock_validate: Mock, mock_resource_config: RSC, resource: str
):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        handler.get_token_verifier(resource)  # type: ignore
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_get_token_verifier_unknown_resource(
    mock_validate: Mock, mock_resource_config: RSC
):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    with pytest.raises(MCPAuthAuthServerException) as excinfo:
        handler.get_token_verifier("unknown-api")
    assert excinfo.value.code == AuthServerExceptionCode.INVALID_SERVER_CONFIG


@patch(
    "mcpauth.auth.resource_server_handler.validate_server_config",
    return_value=type("ValidationResult", (), {"is_valid": True}),
)
def test_create_metadata_route(mock_validate: Mock, mock_resource_config: RSC):
    handler = ResourceServerHandler(
        ResourceServerModeConfig(protected_resources=mock_resource_config)
    )
    router = handler.create_metadata_route()
    client = TestClient(router)

    endpoint_path = create_resource_metadata_endpoint(mock_resource_config.metadata.resource)
    
    response = client.get(endpoint_path)
    assert response.status_code == 200
    assert response.json()["resource"] == "https://my-api.com"
    assert response.json()["authorization_servers"] == ["https://auth.example.com"]

    response = client.options(endpoint_path)
    assert response.status_code == 204 
