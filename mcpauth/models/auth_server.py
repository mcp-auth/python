from enum import Enum
from pydantic import BaseModel
from .oauth import AuthorizationServerMetadata


class AuthServerType(str, Enum):
    """
    The type of the authorization server. This information should be provided by the server
    configuration and indicates whether the server is an OAuth 2.0 or OpenID Connect (OIDC)
    authorization server.
    """

    OAUTH = "oauth"
    OIDC = "oidc"


class AuthServerConfig(BaseModel):
    """
    Configuration for the remote authorization server integrated with the MCP server.
    """

    metadata: AuthorizationServerMetadata
    """
    The metadata of the authorization server, which should conform to the MCP specification
    (based on OAuth 2.0 Authorization Server Metadata).

    This metadata is typically fetched from the server's well-known endpoint (OAuth 2.0
    Authorization Server Metadata or OpenID Connect Discovery); it can also be provided
    directly in the configuration if the server does not support such endpoints.

    See:
    - OAuth 2.0 Authorization Server Metadata: https://datatracker.ietf.org/doc/html/rfc8414
    - OpenID Connect Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
    """

    type: AuthServerType
    """
    The type of the authorization server. See `AuthServerType` for possible values.
    """
