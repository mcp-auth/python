from enum import Enum
from typing import List, Optional
from pydantic import BaseModel


class AuthorizationServerMetadata(BaseModel):
    """
    Pydantic model for OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
    """

    issuer: str
    """
    The authorization server's issuer identifier, which is a URL that uses the `https` scheme and
    has no query or fragment components.
    """

    authorization_endpoint: str
    """
    URL of the authorization server's authorization endpoint [[RFC6749](https://rfc-editor.org/rfc/rfc6749)].
    This is REQUIRED unless no grant types are supported that use the authorization endpoint.

    See: https://rfc-editor.org/rfc/rfc6749#section-3.1
    """

    token_endpoint: str
    """
    URL of the authorization server's token endpoint [[RFC6749](https://rfc-editor.org/rfc/rfc6749)].
    This is REQUIRED unless only the implicit grant type is supported.

    See: https://rfc-editor.org/rfc/rfc6749#section-3.2
    """

    jwks_uri: Optional[str] = None
    """
    URL of the authorization server's JWK Set [[JWK](https://www.rfc-editor.org/rfc/rfc8414.html#ref-JWK)] document.
    The referenced document contains the signing key(s) the client uses to validate signatures 
    from the authorization server. This URL MUST use the `https` scheme.
    """

    registration_endpoint: Optional[str] = None
    """
    URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint 
    [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
    """

    scope_supported: Optional[List[str]] = None

    response_types_supported: List[str]
    """
    JSON array containing a list of the OAuth 2.0 `response_type` values that this authorization
    server supports. The array values used are the same as those used with the `response_types`
    parameter defined by "OAuth 2.0 Dynamic Client Registration Protocol" [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
    """

    response_modes_supported: Optional[List[str]] = None
    """
    JSON array containing a list of the OAuth 2.0 `response_mode` values that this
    authorization server supports, as specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
    [[OAuth.Responses](https://datatracker.ietf.org/doc/html/rfc8414#ref-OAuth.Responses)].

    If omitted, the default is ["query", "fragment"]. The response mode value `"form_post"` is
    also defined in "OAuth 2.0 Form Post Response Mode" [[OAuth.FormPost](https://datatracker.ietf.org/doc/html/rfc8414#ref-OAuth.Post)].
    """

    grant_types_supported: Optional[List[str]] = None
    """
    JSON array containing a list of the OAuth 2.0 grant type values that this authorization server supports.
    The array values used are the same as those used with the `grant_types` parameter defined by 
    "OAuth 2.0 Dynamic Client Registration Protocol" [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].

    If omitted, the default value is ["authorization_code", "implicit"].
    """

    token_endpoint_auth_methods_supported: Optional[List[str]] = None
    token_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None
    service_documentation: Optional[str] = None
    ui_locales_supported: Optional[List[str]] = None
    op_policy_uri: Optional[str] = None
    op_tos_uri: Optional[str] = None

    revocation_endpoint: Optional[str] = None
    """
    URL of the authorization server's OAuth 2.0 revocation endpoint [[RFC7009](https://www.rfc-editor.org/rfc/rfc7009)].
    """

    revocation_endpoint_auth_methods_supported: Optional[List[str]] = None
    revocation_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None

    introspection_endpoint: Optional[str] = None
    """
    URL of the authorization server's OAuth 2.0 introspection endpoint [[RFC7662](https://www.rfc-editor.org/rfc/rfc7662)].
    """

    introspection_endpoint_auth_methods_supported: Optional[List[str]] = None
    introspection_endpoint_auth_signing_alg_values_supported: Optional[List[str]] = None

    code_challenge_methods_supported: Optional[List[str]] = None
    """
    JSON array containing a list of Proof Key for Code Exchange (PKCE) [[RFC7636](https://www.rfc-editor.org/rfc/rfc7636)] 
    code challenge methods supported by this authorization server.
    """

    userinfo_endpoint: Optional[str] = None
    """
    URL of the authorization server's UserInfo endpoint [[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)].
    """


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


class ServerMetadataPaths(str, Enum):
    """
    Enum for server metadata paths.
    This is used to define the standard paths for OAuth and OIDC well-known URLs.
    """

    OAUTH = "/.well-known/oauth-authorization-server"
    OIDC = "/.well-known/openid-configuration"
