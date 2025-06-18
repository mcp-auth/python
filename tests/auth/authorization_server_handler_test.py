import pytest
from unittest.mock import patch
import logging
from pytest import LogCaptureFixture

from starlette.testclient import TestClient
from starlette.routing import Route

from mcpauth.auth.authorization_server_handler import (
    AuthorizationServerHandler,
    AuthServerModeConfig,
)
from mcpauth.config import (
    AuthServerConfig,
    AuthServerType,
    AuthorizationServerMetadata,
    ServerMetadataPaths,
)
from mcpauth.exceptions import MCPAuthAuthServerException
from mcpauth.utils import (
    AuthServerConfigValidationResult,
    AuthServerConfigError,
    AuthServerConfigErrorCode,
    AuthServerConfigWarning,
    AuthServerConfigWarningCode,
)


@pytest.fixture
def valid_auth_server_config() -> AuthServerConfig:
    return AuthServerConfig(
        metadata=AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/auth",
            token_endpoint="https://auth.example.com/token",
            response_types_supported=["code"],
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
        ),
        type=AuthServerType.OAUTH,
    )


def test_init_success(valid_auth_server_config: AuthServerConfig):
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate:
        mock_validate.return_value = AuthServerConfigValidationResult(
            is_valid=True, errors=[], warnings=[]
        )
        handler = AuthorizationServerHandler(
            AuthServerModeConfig(server=valid_auth_server_config)
        )
        assert handler.server == valid_auth_server_config
        assert handler.token_verifier is not None
        mock_validate.assert_called_once_with(valid_auth_server_config)


def test_init_invalid_config(valid_auth_server_config: AuthServerConfig):
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate:
        mock_error = AuthServerConfigError(
            code=AuthServerConfigErrorCode.INVALID_SERVER_METADATA,
            description="some error",
            cause=None,
        )
        mock_validate.return_value = AuthServerConfigValidationResult(
            is_valid=False, errors=[mock_error], warnings=[]
        )
        with pytest.raises(MCPAuthAuthServerException):
            AuthorizationServerHandler(
                AuthServerModeConfig(server=valid_auth_server_config)
            )


def test_init_with_warnings(
    valid_auth_server_config: AuthServerConfig, caplog: LogCaptureFixture
):
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate, caplog.at_level(logging.WARNING):
        mock_warning = AuthServerConfigWarning(
            code=AuthServerConfigWarningCode.DYNAMIC_REGISTRATION_NOT_SUPPORTED,
            description="some warning",
        )
        mock_validate.return_value = AuthServerConfigValidationResult(
            is_valid=True, warnings=[mock_warning], errors=[]
        )
        AuthorizationServerHandler(
            AuthServerModeConfig(server=valid_auth_server_config)
        )
        assert "some warning" in caplog.text


def test_create_metadata_route(valid_auth_server_config: AuthServerConfig):
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate:
        mock_validate.return_value = AuthServerConfigValidationResult(
            is_valid=True, errors=[], warnings=[]
        )
        handler = AuthorizationServerHandler(
            AuthServerModeConfig(server=valid_auth_server_config)
        )
        router = handler.create_metadata_route()
        assert len(router.routes) == 1
        route = router.routes[0]
        assert isinstance(route, Route)
        assert route.path == ServerMetadataPaths.OAUTH.value
        assert route.methods is not None
        assert "GET" in route.methods
        assert "OPTIONS" in route.methods


def test_metadata_endpoint(valid_auth_server_config: AuthServerConfig):
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate:
        mock_validate.return_value = AuthServerConfigValidationResult(
            is_valid=True, errors=[], warnings=[]
        )
        handler = AuthorizationServerHandler(
            AuthServerModeConfig(server=valid_auth_server_config)
        )
        client = TestClient(handler.create_metadata_route())

        # Test GET
        response = client.get(ServerMetadataPaths.OAUTH.value)
        assert response.status_code == 200
        assert response.json() == valid_auth_server_config.metadata.model_dump(
            exclude_none=True
        )
        assert response.headers["access-control-allow-origin"] == "*"

        # Test OPTIONS
        response = client.options(ServerMetadataPaths.OAUTH.value)
        assert response.status_code == 204
        assert response.text == ""
        assert response.headers["access-control-allow-origin"] == "*"


def test_get_token_verifier(valid_auth_server_config: AuthServerConfig):
    with patch(
        "mcpauth.auth.authorization_server_handler.validate_server_config"
    ) as mock_validate:
        mock_validate.return_value = AuthServerConfigValidationResult(
            is_valid=True, errors=[], warnings=[]
        )
        handler = AuthorizationServerHandler(
            AuthServerModeConfig(server=valid_auth_server_config)
        )
        verifier = handler.get_token_verifier("test-resource")
        assert verifier == handler.token_verifier 
