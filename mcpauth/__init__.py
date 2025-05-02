import logging
from typing import List, Literal, Optional, Union

from .middleware.create_bearer_auth import BearerAuthConfig
from .types import VerifyAccessTokenFunction
from .config import AuthServerConfig
from .exceptions import MCPAuthAuthServerException, AuthServerExceptionCode
from .utils import validate_server_config
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class MCPAuth:
    """
    The main class for the mcp-auth library, which provides methods for creating middleware
    functions for handling OAuth 2.0-related tasks and bearer token auth.

    See Also: https://mcp-auth.dev for more information about the library and its usage.
    """

    def __init__(self, server: AuthServerConfig):
        """
        :param server: Configuration for the remote authorization server.
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

    def metadata_response(self) -> JSONResponse:
        """
        Returns a response containing the server metadata in JSON format with CORS support.
        """
        server_config = self.server

        response = JSONResponse(
            server_config.metadata.model_dump(exclude_none=True),
            status_code=200,
        )
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        return response

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
            BearerAuthConfig(
                issuer=metadata.issuer,
                audience=audience,
                required_scopes=required_scopes,
                show_error_details=show_error_details,
            ),
        )
