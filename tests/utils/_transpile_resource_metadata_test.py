from mcpauth import config, types
from mcpauth.utils._transpile_resource_metadata import transpile_resource_metadata


def test_should_transpile_resource_metadata_to_standard_format():
    config_metadata = types.ResourceServerMetadata(
        resource="https://api.example.com",
        authorization_servers=[
            config.AuthServerConfig(
                type=config.AuthServerType.OIDC,
                metadata=config.AuthorizationServerMetadata(
                    issuer="https://auth.example.com",
                    authorization_endpoint="https://auth.example.com/auth",
                    token_endpoint="https://auth.example.com/token",
                    response_types_supported=["code"],
                ),
            ),
            config.AuthServerConfig(
                type=config.AuthServerType.OIDC,
                metadata=config.AuthorizationServerMetadata(
                    issuer="https://another-auth.example.com",
                    authorization_endpoint="https://another-auth.example.com/auth",
                    token_endpoint="https://another-auth.example.com/token",
                    response_types_supported=["code"],
                ),
            ),
        ],
        scopes_supported=["read", "write"],
    )

    standard_metadata = transpile_resource_metadata(config_metadata)

    assert standard_metadata.resource == "https://api.example.com"
    assert standard_metadata.authorization_servers == [
        "https://auth.example.com",
        "https://another-auth.example.com",
    ]
    assert standard_metadata.scopes_supported == ["read", "write"]
    assert standard_metadata.bearer_methods_supported is None
    assert standard_metadata.resource_documentation is None
    assert standard_metadata.resource_signing_alg_values_supported is None


def test_should_handle_metadata_with_no_authorization_servers():
    config_metadata = types.ResourceServerMetadata(
        resource="https://api.example.com",
        scopes_supported=["read", "write"],
    )

    standard_metadata = transpile_resource_metadata(config_metadata)

    assert standard_metadata.resource == "https://api.example.com"
    assert standard_metadata.scopes_supported == ["read", "write"]
    assert standard_metadata.authorization_servers is None


def test_should_handle_metadata_with_an_empty_authorization_servers_array():
    config_metadata = types.ResourceServerMetadata(
        resource="https://api.example.com",
        authorization_servers=[],
        scopes_supported=["read", "write"],
    )

    standard_metadata = transpile_resource_metadata(config_metadata)

    assert standard_metadata.resource == "https://api.example.com"
    assert standard_metadata.scopes_supported == ["read", "write"]
    assert standard_metadata.authorization_servers is None 
