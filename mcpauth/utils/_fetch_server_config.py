from typing import Callable, Optional
from urllib.parse import urlparse, urlunparse
import requests
import pydantic
from pathlib import Path

from ..types import Record
from ..config import (
    AuthServerConfig,
    AuthServerType,
    ServerMetadataPaths,
    AuthorizationServerMetadata,
)
from ..exceptions import (
    AuthServerExceptionCode,
    MCPAuthAuthServerException,
    MCPAuthConfigException,
)


def _smart_join(*args: str) -> str:
    """
    Joins multiple path components into a single path string, regardless of leading or trailing
    slashes.
    """

    return Path("/".join(arg.strip("/") for arg in args)).as_posix()


def get_oauth_well_known_url(issuer: str) -> str:
    parsed_url = urlparse(issuer)
    new_path = _smart_join(ServerMetadataPaths.OAUTH.value, parsed_url.path)
    return urlunparse(parsed_url._replace(path=new_path))


def get_oidc_well_known_url(issuer: str) -> str:
    parsed = urlparse(issuer)
    new_path = _smart_join(parsed.path, ServerMetadataPaths.OIDC.value)
    return urlunparse(parsed._replace(path=new_path))


def fetch_server_config_by_well_known_url(
    well_known_url: str,
    type: AuthServerType,
    transpile_data: Optional[Callable[[Record], Record]] = None,
) -> AuthServerConfig:
    """
    Fetches the server configuration from the provided well-known URL and validates it against the
    MCP specification.

    If the server metadata does not conform to the expected schema, but you are sure that it is
    compatible, you can provide a `transpile_data` function to transform the metadata into the
    expected format.

    :param well_known_url: The well-known URL to fetch the server configuration from.
    :param type: The type of the authorization server (OAuth or OIDC).
    :param transpile_data: Optional function to transform the fetched data into the expected
    format.
    :return AuthServerConfig: An instance of `AuthServerConfig` containing the server metadata.
    :raises MCPAuthConfigException: If there is an error fetching the server metadata.
    :raises MCPAuthAuthServerException: If the server metadata is invalid or malformed.
    """

    try:
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        json = response.json()
        transpiled_data = transpile_data(json) if transpile_data else json
        return AuthServerConfig(
            metadata=AuthorizationServerMetadata(**transpiled_data), type=type
        )
    except pydantic.ValidationError as e:
        raise MCPAuthAuthServerException(
            AuthServerExceptionCode.INVALID_SERVER_METADATA,
            cause=e,
        ) from e
    except Exception as e:
        raise MCPAuthConfigException(
            "fetch_server_config_error",
            f"Failed to fetch server config from {well_known_url}: {str(e)}",
            cause=e,
        ) from e


def fetch_server_config(
    issuer: str,
    type: AuthServerType,
    transpile_data: Optional[Callable[[Record], Record]] = None,
) -> AuthServerConfig:
    """
    Fetches the server configuration according to the issuer and authorization server type.

    This function automatically determines the well-known URL based on the server type, as OAuth
    and OpenID Connect servers have different conventions for their metadata endpoints.

    See Also:
    - `fetchServerConfigByWellKnownUrl` for the underlying implementation.
    - https://www.rfc-editor.org/rfc/rfc8414 for the OAuth 2.0 Authorization Server Metadata
    specification.
    - https://openid.net/specs/openid-connect-discovery-1_0.html for the OpenID Connect Discovery
    specification.

    Example:
    ```python
    from mcpauth.utils import fetch_server_config, AuthServerType

    # Fetch OAuth server config. This will fetch the metadata from
    # `https://auth.logto.io/.well-known/oauth-authorization-server/oauth`
    oauth_config = await fetch_server_config(
        issuer="https://auth.logto.io/oauth",
        type=AuthServerType.OAUTH
    )

    # Fetch OIDC server config. This will fetch the metadata from
    # `https://auth.logto.io/oidc/.well-known/openid-configuration`
    oidc_config = await fetch_server_config(
        issuer="https://auth.logto.io/oidc",
        type=AuthServerType.OIDC
    )
    ```

    :param issuer: The issuer URL of the authorization server.
    :param type: The type of the authorization server (OAuth or OIDC).
    :param transpile_data: Optional function to transform the fetched data into the expected
    format.
    :return AuthServerConfig: An instance of `AuthServerConfig` containing the server metadata.
    :raises MCPAuthConfigException: If there is an error fetching the server metadata.
    :raises MCPAuthAuthServerException: If the server metadata is invalid or malformed.
    """

    well_known_url = (
        get_oauth_well_known_url(issuer)
        if type == AuthServerType.OAUTH
        else get_oidc_well_known_url(issuer)
    )
    return fetch_server_config_by_well_known_url(well_known_url, type, transpile_data)
