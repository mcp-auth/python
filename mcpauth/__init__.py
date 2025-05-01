import logging
from typing import Any, Literal, Union

from .middleware.create_bearer_auth import BaseBearerAuthConfig, BearerAuthConfig
from .types import VerifyAccessTokenFunction
from .config import MCPAuthConfig
from .exceptions import MCPAuthAuthServerException, AuthServerExceptionCode
from .utils import validate_server_config
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class MCPAuth:
    """
    The main class for the mcp-auth library, which provides methods for creating middleware
    functions for handling OAuth 2.0-related tasks and bearer token auth.

    See Also: https://mcp-auth.dev for more information about the library and its usage.

    :param config: An instance of `MCPAuthConfig` containing the server configuration.
    """

    def __init__(self, config: MCPAuthConfig):
        result = validate_server_config(config.server)

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

        self.config = config

    def metadata_response(self) -> JSONResponse:
        """
        Returns a response containing the server metadata in JSON format with CORS support.
        """
        server_config = self.config.server

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
        config: BaseBearerAuthConfig = BaseBearerAuthConfig(),
        jwt_options: dict[str, Any] = {},
    ) -> type[BaseHTTPMiddleware]:
        """
        Creates a middleware that handles bearer token authentication.

        :param mode_or_verify: If "jwt", uses built-in JWT verification; or a custom function that
        takes a string token and returns an `AuthInfo` object.
        :param config: Configuration for the Bearer auth handler, including audience, required
        scopes, etc.
        :param jwt_options: Optional dictionary of additional options for JWT verification
        (`jwt.decode`). Not used if a custom function is provided.
        :return: A middleware class that can be used in a Starlette or FastAPI application.
        """

        metadata = self.config.server.metadata
        if isinstance(mode_or_verify, str) and mode_or_verify == "jwt":
            from .utils import create_verify_jwt

            if not metadata.jwks_uri:
                raise MCPAuthAuthServerException(
                    AuthServerExceptionCode.MISSING_JWKS_URI
                )

            verify = create_verify_jwt(
                metadata.jwks_uri,
                options=jwt_options,
            )
        elif callable(mode_or_verify):
            verify = mode_or_verify
        else:
            raise ValueError(
                "mode_or_verify must be 'jwt' or a callable function that verifies tokens."
            )

        from .middleware.create_bearer_auth import create_bearer_auth

        return create_bearer_auth(
            verify, BearerAuthConfig(issuer=metadata.issuer, **config.model_dump())
        )
