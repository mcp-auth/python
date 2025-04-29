from enum import Enum
from typing import Callable, Optional
from urllib.parse import urlparse, urlunparse
import aiohttp
import pydantic
from pathlib import Path

from ..types import Record
from ..models.oauth import AuthorizationServerMetadata
from ..models.auth_server import AuthServerConfig, AuthServerType
from ..exceptions import MCPAuthConfigException


class ServerMetadataPaths(str, Enum):
    """
    Enum for server metadata paths.
    This is used to define the standard paths for OAuth and OIDC well-known URLs.
    """

    OAUTH = "/.well-known/oauth-authorization-server"
    OIDC = "/.well-known/openid-configuration"


def smart_join(*args: str) -> str:
    return Path("/".join(arg.strip("/") for arg in args)).as_posix()


def get_oauth_well_known_url(issuer: str) -> str:
    parsed_url = urlparse(issuer)
    new_path = smart_join(ServerMetadataPaths.OAUTH.value, parsed_url.path)
    return urlunparse(parsed_url._replace(path=new_path))


def get_oidc_well_known_url(issuer: str) -> str:
    parsed = urlparse(issuer)
    new_path = smart_join(parsed.path, ServerMetadataPaths.OIDC.value)
    return urlunparse(parsed._replace(path=new_path))


async def fetch_server_config_by_well_known_url(
    well_known_url: str,
    type: AuthServerType,
    transpile_data: Optional[Callable[[Record], Record]] = None,
) -> AuthServerConfig:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(well_known_url) as response:
                response.raise_for_status()
                json = await response.json()
                transpiled_data = transpile_data(json) if transpile_data else json
                return AuthServerConfig(
                    metadata=AuthorizationServerMetadata(**transpiled_data), type=type
                )
    except pydantic.ValidationError as e:
        raise MCPAuthConfigException(
            "invalid_server_metadata",
            f"Invalid server metadata from {well_known_url}: {str(e)}",
            cause=e,
        ) from e
    except Exception as e:
        raise MCPAuthConfigException(
            "fetch_server_config_error",
            f"Failed to fetch server config from {well_known_url}: {str(e)}",
            cause=e,
        ) from e


async def fetch_server_config(
    issuer: str,
    type: AuthServerType,
    transpile_data: Optional[Callable[[Record], Record]] = None,
) -> AuthServerConfig:
    well_known_url = (
        get_oauth_well_known_url(issuer)
        if type == AuthServerType.OAUTH
        else get_oidc_well_known_url(issuer)
    )
    return await fetch_server_config_by_well_known_url(
        well_known_url, type, transpile_data
    )
