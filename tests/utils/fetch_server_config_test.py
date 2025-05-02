import pytest
import responses

from mcpauth.config import AuthServerType, ServerMetadataPaths
from mcpauth.exceptions import MCPAuthAuthServerException, MCPAuthConfigException
from mcpauth.types import Record
from mcpauth.utils import (
    fetch_server_config,
    fetch_server_config_by_well_known_url,
)

sample_issuer = "https://example.com"
sample_well_known_url = sample_issuer + ServerMetadataPaths.OAUTH.value


class TestFetchServerConfigByWellKnownUrl:
    @responses.activate
    def test_fetch_server_config_by_well_known_url_fetch_fails(self):
        responses.add(
            responses.GET,
            url=sample_well_known_url,
            body="Internal Server Error",
            status=500,
        )

        with pytest.raises(MCPAuthConfigException) as exc_info:
            fetch_server_config_by_well_known_url(
                sample_well_known_url, AuthServerType.OAUTH
            )

        assert "Failed to fetch server config" in str(exc_info.value)
        assert "Internal Server Error" in str(exc_info.value)

    @responses.activate
    def test_fetch_server_config_by_well_known_url_invalid_metadata(self):
        responses.add(responses.GET, url=sample_well_known_url, json={}, status=200)

        with pytest.raises(MCPAuthAuthServerException) as exc_info:
            fetch_server_config_by_well_known_url(
                sample_well_known_url, AuthServerType.OAUTH
            )

        assert "The server metadata is invalid or malformed" in str(exc_info.value)

    @responses.activate
    def test_fetch_server_config_by_well_known_url_malformed_metadata(self):
        sample_response = {
            "issuer": sample_issuer,
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
        }

        responses.add(responses.GET, url=sample_well_known_url, json=sample_response)

        with pytest.raises(MCPAuthAuthServerException) as exc_info:
            fetch_server_config_by_well_known_url(
                sample_well_known_url, AuthServerType.OAUTH
            )

        assert "The server metadata is invalid or malformed" in str(exc_info.value)

    @responses.activate
    def test_fetch_server_config_by_well_known_url_success_with_transpile(self):
        sample_response = {
            "issuer": sample_issuer,
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
        }

        responses.add(responses.GET, url=sample_well_known_url, json=sample_response)

        config = fetch_server_config_by_well_known_url(
            sample_well_known_url,
            type=AuthServerType.OAUTH,
            transpile_data=lambda data: {**data, "response_types_supported": ["code"]},
        )

        assert config.type == AuthServerType.OAUTH
        assert config.metadata.issuer == sample_issuer
        assert (
            config.metadata.authorization_endpoint
            == "https://example.com/oauth/authorize"
        )
        assert config.metadata.token_endpoint == "https://example.com/oauth/token"
        assert config.metadata.response_types_supported == ["code"]

    @responses.activate
    def test_fetch_server_config_oauth_success(self):
        sample_response: Record = {
            "issuer": sample_issuer + "/",
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
            "response_types_supported": ["code"],
        }

        responses.add(
            responses.GET,
            url=sample_issuer + ServerMetadataPaths.OAUTH.value,
            json=sample_response,
        )

        config = fetch_server_config(sample_issuer, AuthServerType.OAUTH)

        assert config.type == AuthServerType.OAUTH
        assert config.metadata.issuer == sample_issuer + "/"
        assert (
            config.metadata.authorization_endpoint
            == "https://example.com/oauth/authorize"
        )
        assert config.metadata.token_endpoint == "https://example.com/oauth/token"
        assert config.metadata.response_types_supported == ["code"]

    @responses.activate
    def test_fetch_server_config_oauth_with_path_success(self):
        issuer = "https://example.com/path"
        sample_response: Record = {
            "issuer": issuer,
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
            "response_types_supported": ["code"],
        }

        responses.add(
            responses.GET,
            url="https://example.com" + ServerMetadataPaths.OAUTH.value + "/path",
            json=sample_response,
        )

        config = fetch_server_config(issuer, AuthServerType.OAUTH)

        assert config.type == AuthServerType.OAUTH
        assert config.metadata.issuer == issuer
        assert (
            config.metadata.authorization_endpoint
            == "https://example.com/oauth/authorize"
        )
        assert config.metadata.token_endpoint == "https://example.com/oauth/token"
        assert config.metadata.response_types_supported == ["code"]

    @responses.activate
    def test_fetch_server_config_oidc_success(self):
        sample_response: Record = {
            "issuer": sample_issuer + "/",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code"],
        }

        responses.add(
            responses.GET,
            sample_issuer + ServerMetadataPaths.OIDC.value,
            json=sample_response,
        )

        config = fetch_server_config(sample_issuer, AuthServerType.OIDC)

        assert config.type == AuthServerType.OIDC
        assert config.metadata.issuer == sample_issuer + "/"
        assert config.metadata.authorization_endpoint == "https://example.com/authorize"
        assert config.metadata.token_endpoint == "https://example.com/token"
        assert config.metadata.response_types_supported == ["code"]

    @responses.activate
    def test_fetch_server_config_oidc_with_path_success(self):
        issuer = "https://example.com/path"
        sample_response: Record = {
            "issuer": issuer,
            "authorization_endpoint": issuer + "/authorize",
            "token_endpoint": issuer + "/token",
            "response_types_supported": ["code"],
        }

        responses.add(
            responses.GET,
            issuer + ServerMetadataPaths.OIDC.value,
            json=sample_response,
        )

        config = fetch_server_config(issuer, AuthServerType.OIDC)

        assert config.type == AuthServerType.OIDC
        assert config.metadata.issuer == issuer
        assert config.metadata.authorization_endpoint == issuer + "/authorize"
        assert config.metadata.token_endpoint == issuer + "/token"
        assert config.metadata.response_types_supported == ["code"]

    @responses.activate
    def test_fetch_server_config_oidc_failure(self):
        responses.add(
            responses.GET,
            url=sample_issuer + ServerMetadataPaths.OIDC.value,
            body="Internal Server Error",
            status=500,
        )

        with pytest.raises(MCPAuthConfigException) as exc_info:
            fetch_server_config(sample_issuer, AuthServerType.OIDC)

        assert "Failed to fetch server config" in str(exc_info.value)
