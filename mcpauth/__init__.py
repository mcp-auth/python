from contextvars import ContextVar
from typing import Callable, List, Literal, Optional, Union
from typing_extensions import deprecated

from .auth.authorization_server_handler import (
    AuthorizationServerHandler,
    AuthServerModeConfig,
)
from .auth.mcp_auth_handler import MCPAuthHandler
from .auth.resource_server_handler import (
    ResourceServerHandler,
    ResourceServerModeConfig,
)
from .middleware.create_bearer_auth import BearerAuthConfig
from .types import AuthInfo, ResourceServerConfig, VerifyAccessTokenFunction
from .config import AuthServerConfig
from .exceptions import MCPAuthAuthServerException, AuthServerExceptionCode
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Router, Route

_context_var_name = "mcp_auth_context"


class MCPAuth:
    """
    The main class for the mcp-auth library, which provides methods for creating middleware
    functions for handling OAuth 2.0-related tasks and bearer token auth.

    See Also: https://mcp-auth.dev for more information about the library and its usage.
    """

    _handler: MCPAuthHandler

    def __init__(
        self,
        server: Optional[AuthServerConfig] = None,
        protected_resources: Optional[
            Union[ResourceServerConfig, List[ResourceServerConfig]]
        ] = None,
        context_var: ContextVar[Optional[AuthInfo]] = ContextVar(
            _context_var_name, default=None
        ),
    ):
        """
        :param server: Configuration for the remote authorization server (deprecated).
        :param protected_resources: Configuration for one or more protected resource servers.
        :param context_var: Context variable to store the `AuthInfo` object for the current request.
        By default, it will be created with the name "mcp_auth_context".
        """

        if server and protected_resources:
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                cause={
                    "error_description": "Either `server` or `protected_resources` must be provided, but not both."
                },
            )

        if server:
            self._handler = AuthorizationServerHandler(AuthServerModeConfig(server))
        elif protected_resources:
            self._handler = ResourceServerHandler(
                ResourceServerModeConfig(protected_resources)
            )
        else:
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                cause={
                    "error_description": "Either `server` or `protected_resources` must be provided."
                },
            )

        self._context_var = context_var

    @property
    def auth_info(self) -> Optional[AuthInfo]:
        """
        The current `AuthInfo` object from the context variable.

        This is useful for accessing the authenticated user's information in later middleware or
        route handlers.
        :return: The current `AuthInfo` object, or `None` if not set.
        """

        return self._context_var.get()

    @deprecated("Use resource_metadata_router() instead for resource server mode")
    def metadata_route(self) -> Route:
        """
        Returns a router that handles the legacy OAuth 2.0 Authorization Server Metadata endpoint.
        
        This method is deprecated and will be removed in a future version.
        For resource server mode, use `resource_metadata_router()` instead to serve
        the Protected Resource Metadata endpoints.
        """
        if isinstance(self._handler, ResourceServerHandler):
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                cause={
                    "error_description": "`metadata_route` is not available in `resource server` mode. Use `resource_metadata_router()` instead."
                },
            )

        oauth_metadata_route = self._handler.create_metadata_route().routes[0]

        if not isinstance(oauth_metadata_route, Route):
            raise IndexError(
                "No metadata endpoint route was created. Expected the authorization server metadata route to be present."
            )

        return oauth_metadata_route

    def resource_metadata_router(self) -> Router:
        """
        Returns a router that serves the OAuth 2.0 Protected Resource Metadata endpoint
        for all configured resources.

        This is an alias for `metadata_route` and is the recommended method to use when
        in "resource server" mode.
        """
        if isinstance(self._handler, AuthorizationServerHandler):
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                cause={
                    "error_description": "`resource_metadata_router` is not available in `authorization server` mode."
                },
            )
        return self._handler.create_metadata_route()

    def bearer_auth_middleware(
        self,
        mode_or_verify: Union[Literal["jwt"], VerifyAccessTokenFunction],
        audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        show_error_details: bool = False,
        leeway: float = 60,
        resource: Optional[str] = None,
    ) -> type[BaseHTTPMiddleware]:
        """
        Creates a middleware that handles bearer token authentication.

        :param mode_or_verify: If "jwt", uses built-in JWT verification; or a custom function that
        takes a string token and returns an `AuthInfo` object.
        :param audience: Optional audience to verify against the token.
        :param required_scopes: Optional list of scopes that the token must contain.
        :param show_error_details: Whether to include detailed error information in the response.
        Defaults to `False`.
        :param leeway: Optional leeway in seconds for JWT verification (`jwt.decode`). Defaults to
        `60`. Not used if a custom function is provided.
        :param resource: The identifier of the protected resource. Required when using `protected_resources`.
        :return: A middleware class that can be used in a Starlette or FastAPI application.
        """
        from .middleware.create_bearer_auth import create_bearer_auth

        issuer: Union[str, Callable[[str], None]]

        resource_for_verifier: str

        if isinstance(self._handler, ResourceServerHandler):
            if not resource:
                raise MCPAuthAuthServerException(
                    AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                    cause={
                        "error_description": "A `resource` must be specified in the `bearer_auth_middleware` configuration when using a `protected_resources` configuration."
                    },
                )
            resource_for_verifier = resource
        else: # AuthorizationServerHandler
            # In the deprecated `authorization server` mode, `getTokenVerifier` does not utilize the
            # `resource` parameter. Passing an empty string `''` is a straightforward approach that
            # avoids over-engineering a solution for a legacy path.
            resource_for_verifier = ""

        if isinstance(mode_or_verify, str) and mode_or_verify == "jwt":
            token_verifier = self._handler.get_token_verifier(
                resource=resource_for_verifier
            )
            verify = token_verifier.create_verify_jwt_function(leeway=leeway)
            issuer = token_verifier.validate_jwt_issuer
        elif callable(mode_or_verify):
            verify = mode_or_verify
            # For custom verify functions, issuer validation should be handled by the custom logic
            issuer = lambda _: None  # No-op function that accepts any issuer
        else:
            raise ValueError(
                "mode_or_verify must be 'jwt' or a callable function that verifies tokens."
            )

        return create_bearer_auth(
            verify,
            config=BearerAuthConfig(
                issuer=issuer,
                audience=audience,
                required_scopes=required_scopes,
                show_error_details=show_error_details,
                resource=resource,
            ),
            context_var=self._context_var,
        )
