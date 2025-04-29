import pytest
from aresponses import ResponsesMockServer
from aiohttp.web_response import Response

from mcpauth.models.auth_server import AuthServerType
from mcpauth.exceptions import MCPAuthConfigException
from mcpauth.types import Record
from mcpauth.utils.fetch_server_config import (
    ServerMetadataPaths,
    fetch_server_config,
    fetch_server_config_by_well_known_url,
)


@pytest.mark.asyncio
class TestFetchServerConfigByWellKnownUrl:
    async def test_fetch_server_config_by_well_known_url_fetch_fails(
        self, aresponses: ResponsesMockServer
    ):
        sample_issuer = "https://example.com"
        sample_well_known_url = sample_issuer + ServerMetadataPaths.OAUTH.value

        aresponses.add(
            "example.com",
            ServerMetadataPaths.OAUTH.value,
            "GET",
            Response(text="Internal Server Error", status=500),
        )

        with pytest.raises(MCPAuthConfigException) as exc_info:
            await fetch_server_config_by_well_known_url(
                sample_well_known_url, AuthServerType.OAUTH
            )

        assert "Failed to fetch server config" in str(exc_info.value)

    async def test_fetch_server_config_by_well_known_url_invalid_metadata(
        self, aresponses: ResponsesMockServer
    ):
        sample_issuer = "https://example.com"
        sample_well_known_url = sample_issuer + ServerMetadataPaths.OAUTH.value

        aresponses.add(
            "example.com", ServerMetadataPaths.OAUTH.value, "GET", response={}
        )

        with pytest.raises(MCPAuthConfigException) as exc_info:
            await fetch_server_config_by_well_known_url(
                sample_well_known_url, AuthServerType.OAUTH
            )

        assert "Invalid server metadata" in str(exc_info.value)

    async def test_fetch_server_config_by_well_known_url_malformed_metadata(
        self, aresponses: ResponsesMockServer
    ):
        sample_issuer = "https://example.com"
        sample_well_known_url = sample_issuer + ServerMetadataPaths.OAUTH.value

        sample_response = {
            "issuer": sample_issuer,
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
        }

        aresponses.add(
            "example.com", ServerMetadataPaths.OAUTH.value, "GET", sample_response
        )

        with pytest.raises(MCPAuthConfigException) as exc_info:
            await fetch_server_config_by_well_known_url(
                sample_well_known_url, AuthServerType.OAUTH
            )

        assert "Invalid server metadata" in str(exc_info.value)

    async def test_fetch_server_config_by_well_known_url_success_with_transpile(
        self, aresponses: ResponsesMockServer
    ):
        sample_issuer = "https://example.com"
        sample_well_known_url = sample_issuer + ServerMetadataPaths.OAUTH.value

        sample_response = {
            "issuer": sample_issuer,
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
        }

        def transpile(data: Record) -> Record:
            return {**data, "response_types_supported": ["code"]}

        aresponses.add(
            "example.com",
            ServerMetadataPaths.OAUTH.value,
            "GET",
            sample_response,
        )

        config = await fetch_server_config_by_well_known_url(
            sample_well_known_url,
            AuthServerType.OAUTH,
            transpile_data=transpile,
        )

        assert config.type == AuthServerType.OAUTH
        assert config.metadata.issuer == sample_issuer
        assert (
            config.metadata.authorization_endpoint
            == "https://example.com/oauth/authorize"
        )
        assert config.metadata.token_endpoint == "https://example.com/oauth/token"
        assert config.metadata.response_types_supported == ["code"]

    async def test_fetch_server_config_oauth_success(
        self, aresponses: ResponsesMockServer
    ):
        issuer = "https://example.com"
        sample_response: Record = {
            "issuer": issuer + "/",
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
            "response_types_supported": ["code"],
        }

        aresponses.add(
            "example.com",
            ServerMetadataPaths.OAUTH.value,
            "GET",
            sample_response,
        )

        config = await fetch_server_config(issuer, AuthServerType.OAUTH)

        assert config.type == AuthServerType.OAUTH
        assert config.metadata.issuer == issuer + "/"
        assert (
            config.metadata.authorization_endpoint
            == "https://example.com/oauth/authorize"
        )
        assert config.metadata.token_endpoint == "https://example.com/oauth/token"
        assert config.metadata.response_types_supported == ["code"]

    async def test_fetch_server_config_oauth_with_path_success(
        self, aresponses: ResponsesMockServer
    ):
        issuer = "https://example.com/path"
        sample_response: Record = {
            "issuer": issuer,
            "authorization_endpoint": "https://example.com/oauth/authorize",
            "token_endpoint": "https://example.com/oauth/token",
            "response_types_supported": ["code"],
        }

        aresponses.add(
            "example.com",
            ServerMetadataPaths.OAUTH.value + "/path",
            "GET",
            sample_response,
        )

        config = await fetch_server_config(issuer, AuthServerType.OAUTH)

        assert config.type == AuthServerType.OAUTH
        assert config.metadata.issuer == issuer
        assert (
            config.metadata.authorization_endpoint
            == "https://example.com/oauth/authorize"
        )
        assert config.metadata.token_endpoint == "https://example.com/oauth/token"
        assert config.metadata.response_types_supported == ["code"]

    async def test_fetch_server_config_oidc_success(
        self, aresponses: ResponsesMockServer
    ):
        issuer = "https://example.com"
        sample_response: Record = {
            "issuer": issuer + "/",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code"],
        }

        aresponses.add(
            "example.com",
            ServerMetadataPaths.OIDC.value,
            "GET",
            sample_response,
        )

        config = await fetch_server_config(issuer, AuthServerType.OIDC)

        assert config.type == AuthServerType.OIDC
        assert config.metadata.issuer == issuer + "/"
        assert config.metadata.authorization_endpoint == "https://example.com/authorize"
        assert config.metadata.token_endpoint == "https://example.com/token"
        assert config.metadata.response_types_supported == ["code"]

    async def test_fetch_server_config_oidc_with_path_success(
        self, aresponses: ResponsesMockServer
    ):
        issuer = "https://example.com/path"
        sample_response: Record = {
            "issuer": issuer,
            "authorization_endpoint": issuer + "/authorize",
            "token_endpoint": issuer + "/token",
            "response_types_supported": ["code"],
        }

        aresponses.add(
            "example.com",
            "/path/.well-known/openid-configuration",
            "GET",
            sample_response,
        )

        config = await fetch_server_config(issuer, AuthServerType.OIDC)

        assert config.type == AuthServerType.OIDC
        assert config.metadata.issuer == issuer
        assert config.metadata.authorization_endpoint == issuer + "/authorize"
        assert config.metadata.token_endpoint == issuer + "/token"
        assert config.metadata.response_types_supported == ["code"]

    async def test_fetch_server_config_oidc_failure(
        self, aresponses: ResponsesMockServer
    ):
        issuer = "https://example.com"

        aresponses.add(
            "example.com",
            ServerMetadataPaths.OIDC.value,
            "GET",
            Response(text="Internal Server Error", status=500),
        )

        with pytest.raises(MCPAuthConfigException) as exc_info:
            await fetch_server_config(issuer, AuthServerType.OIDC)

        assert "Failed to fetch server config" in str(exc_info.value)
