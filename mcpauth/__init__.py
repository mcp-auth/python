from contextvars import ContextVar
import logging
from typing import Any, Callable, List, Literal, Optional, Union

from .middleware.create_bearer_auth import BearerAuthConfig
from .types import AuthInfo, VerifyAccessTokenFunction
from .config import AuthServerConfig, ServerMetadataPaths
from .exceptions import MCPAuthAuthServerException, AuthServerExceptionCode
from .utils import validate_server_config
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from starlette.requests import Request
from starlette.routing import Route

_context_var_name = "mcp_auth_context"


class MCPAuth:
    """
    The main class for the mcp-auth library, which provides methods for creating middleware
    functions for handling OAuth 2.0-related tasks and bearer token auth.

    See Also: https://mcp-auth.dev for more information about the library and its usage.
    """

    server: AuthServerConfig
    """
    The configuration for the remote authorization server.
    """

    def __init__(
        self,
        server: AuthServerConfig,
        context_var: ContextVar[Optional[AuthInfo]] = ContextVar(
            _context_var_name, default=None
        ),
    ):
        """
        :param server: Configuration for the remote authorization server.
        :param context_var: Context variable to store the `AuthInfo` object for the current request.
        By default, it will be created with the name "mcp_auth_context".
        """

        result = validate_server_config(server)

        if not result.is_valid:
            logging.error(
                "The authorization server configuration is invalid:\n"
                f"{result.errors}\n"
            )
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG, cause=result
            )

        if len(result.warnings) > 0:
            logging.warning("The authorization server configuration has warnings:\n")
            for warning in result.warnings:
                logging.warning(f"- {warning}")

        self.server = server
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

    def metadata_endpoint(self) -> Callable[[Request], Any]:
        """
        Returns a Starlette endpoint function that handles the OAuth 2.0 Authorization Metadata
        endpoint (`/.well-known/oauth-authorization-server`) with CORS support.

        Example:
        ```python
        from starlette.applications import Starlette
        from mcpauth import MCPAuth
        from mcpauth.config import ServerMetadataPaths

        mcp_auth = MCPAuth(server=your_server_config)
        app = Starlette(routes=[
            Route(
                ServerMetadataPaths.OAUTH.value,
                mcp_auth.metadata_endpoint(),
                methods=["GET", "OPTIONS"] # Ensure to handle both GET and OPTIONS methods
            )
        ])
        ```
        """

        async def endpoint(request: Request) -> Response:
            if request.method == "OPTIONS":
                response = Response(status_code=204)
            else:
                server_config = self.server
                response = JSONResponse(
                    server_config.metadata.model_dump(exclude_none=True),
                    status_code=200,
                )
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            return response

        return endpoint

    def metadata_route(self) -> Route:
        """
        Returns a Starlette route that handles the OAuth 2.0 Authorization Metadata endpoint
        (`/.well-known/oauth-authorization-server`) with CORS support.

        Example:
        ```python
        from starlette.applications import Starlette
        from mcpauth import MCPAuth

        mcp_auth = MCPAuth(server=your_server_config)
        app = Starlette(routes=[mcp_auth.metadata_route()])
        ```
        """

        return Route(
            ServerMetadataPaths.OAUTH.value,
            self.metadata_endpoint(),
            methods=["GET", "OPTIONS"],
        )

    def bearer_auth_middleware(
        self,
        mode_or_verify: Union[Literal["jwt"], VerifyAccessTokenFunction],
        audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        show_error_details: bool = False,
        leeway: float = 60,
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
        :return: A middleware class that can be used in a Starlette or FastAPI application.
        """

        metadata = self.server.metadata
        if isinstance(mode_or_verify, str) and mode_or_verify == "jwt":
            from .utils import create_verify_jwt

            if not metadata.jwks_uri:
                raise MCPAuthAuthServerException(
                    AuthServerExceptionCode.MISSING_JWKS_URI
                )

            verify = create_verify_jwt(
                metadata.jwks_uri,
                leeway=leeway,
            )
        elif callable(mode_or_verify):
            verify = mode_or_verify
        else:
            raise ValueError(
                "mode_or_verify must be 'jwt' or a callable function that verifies tokens."
            )

        from .middleware.create_bearer_auth import create_bearer_auth

        return create_bearer_auth(
            verify,
            config=BearerAuthConfig(
                issuer=metadata.issuer,
                audience=audience,
                required_scopes=required_scopes,
                show_error_details=show_error_details,
            ),
            context_var=self._context_var,
        )
