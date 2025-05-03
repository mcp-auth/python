from typing import Annotated, Dict, List, Optional, Protocol, Union, Any
from pydantic import BaseModel, StringConstraints


Record = Dict[str, Any]


class AuthInfo(BaseModel):
    """
    Authentication information extracted from tokens.

    These fields can be used in the MCP handlers to provide more context about the authenticated
    identity.
    """

    token: str
    """
    The raw access token received in the request. This is typically a JWT or opaque token that is
    used to authenticate the request.
    """

    issuer: str
    """
    The issuer of the access token, which is typically the OAuth / OIDC provider that issued the token.
    This is usually a URL that identifies the authorization server.

    See Also:
    - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
    - https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier
    """

    client_id: Optional[str] = None
    """
    The client ID of the OAuth client that the token was issued to. This is typically the client ID
    registered with the OAuth / OIDC provider.

    Some providers may use 'application ID' or similar terms instead of 'client ID'.
    """

    scopes: List[str] = []
    """
    The scopes (permissions) that the access token has been granted. Scopes define what actions the
    token can perform on behalf of the user or client. Normally, you need to define these scopes in
    the OAuth / OIDC provider and assign them to the `subject` of the token.

    The provider may support different mechanisms for defining and managing scopes, such as
    role-based access control (RBAC) or fine-grained permissions.
    """

    subject: str
    """
    The `sub` (subject) claim of the token, which typically represents the user ID or principal
    that the token is issued for.

    See Also:
    - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
    """

    audience: Optional[Union[str, List[str]]] = None
    """
    The `aud` (audience) claim of the token, which indicates the intended recipient(s) of the token.

    For OAuth / OIDC providers that support Resource Indicators (RFC 8707), this claim can be used
    to specify the intended Resource Server (API) that the token is meant for.

    If the token is intended for multiple audiences, this can be a list of strings.

    See Also:
    - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
    - https://datatracker.ietf.org/doc/html/rfc8707
    """

    claims: Dict[str, Any]
    """
    The raw claims from the token, which can include any additional information provided by the
    token issuer.
    """


class VerifyAccessTokenFunction(Protocol):
    """
    Function type for verifying an access token.

    This function should throw an `MCPAuthTokenVerificationException` if the token is invalid, or return an
    `AuthInfo` instance if the token is valid.

    For example, if you have a JWT verification function, it should at least check the token's
    signature, validate its expiration, and extract the necessary claims to return an `AuthInfo`
    instance.

    Note:
        There's no need to verify the following fields in the token, as they will be checked
        by the MCP handlers:

        - `iss` (issuer)
        - `aud` (audience)
        - `scope` (scopes)
    """

    def __call__(self, token: str) -> AuthInfo:
        """
        :param token: The access token to verify.
        :return: An `AuthInfo` instance containing the extracted authentication information.
        """
        ...


NonEmptyString = Annotated[str, StringConstraints(min_length=1)]


class JwtPayload(BaseModel):
    """
    The base model for JWT (JSON Web Token) payload claims.
    This model defines the common claims that are expected in a JWT used for authentication and
    authorization.
    """

    aud: Optional[Union[NonEmptyString, List[NonEmptyString]]] = None
    """
    The `aud` (audience) claim of the token, which indicates the intended recipient(s) of the token.

    For OAuth / OIDC providers that support Resource Indicators (RFC 8707), this claim can be used
    to specify the intended Resource Server (API) that the token is meant for.

    If the token is intended for multiple audiences, this can be a list of strings.

    See Also:
    - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
    - https://datatracker.ietf.org/doc/html/rfc8707
    """

    iss: NonEmptyString
    """
    The issuer of the access token, which is typically the OAuth / OIDC provider that issued the token.
    This is usually a URL that identifies the authorization server.

    See Also:
    - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
    - https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier
    """

    client_id: NonEmptyString
    """
    The client ID of the OAuth client that the token was issued to. This is typically the client ID
    registered with the OAuth / OIDC provider.

    Some providers may use 'application ID' or similar terms instead of 'client ID'.
    """

    sub: NonEmptyString
    """
    The `sub` (subject) claim of the token, which typically represents the user ID or principal
    that the token is issued for.

    See Also:
    - https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
    """

    scope: Optional[Union[str, List[str]]] = None
    """
    The scopes (permissions) that the access token has been granted. Scopes define what actions the
    token can perform on behalf of the user or client. Normally, you need to define these scopes in
    the OAuth / OIDC provider and assign them to the `subject` of the token.

    The provider may support different mechanisms for defining and managing scopes, such as
    role-based access control (RBAC) or fine-grained permissions.
    """

    scopes: Optional[Union[str, List[str]]] = None
    """
    The fallback for the `scope` claim.
    """

    exp: Optional[int] = None
    """
    The expiration time of the access token, represented as a Unix timestamp (seconds since epoch).
    """
