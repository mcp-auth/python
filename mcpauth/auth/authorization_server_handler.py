import logging
from typing import Any, Callable

from starlette.routing import Route, Router
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from ..config import AuthServerConfig, ServerMetadataPaths
from ..exceptions import AuthServerExceptionCode, MCPAuthAuthServerException
from ..utils import validate_server_config
from .mcp_auth_handler import MCPAuthHandler
from .token_verifier import TokenVerifier


class AuthServerModeConfig:
    """
    Configuration for the legacy, MCP-server-as-authorization-server mode.
    """

    def __init__(self, server: AuthServerConfig):
        self.server = server


class AuthorizationServerHandler(MCPAuthHandler):
    """
    Handles the authentication logic for the legacy `server` mode.
    """

    def __init__(self, config: AuthServerModeConfig):
        logging.warning(
            "The authorization server mode is deprecated. Please use resource server mode instead."
        )

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

        self.server = config.server
        self.token_verifier = TokenVerifier([config.server])

    def create_metadata_route(self) -> Router:
        """
        Returns a Starlette route that handles the OAuth 2.0 Authorization Metadata endpoint
        (`/.well-known/oauth-authorization-server`) with CORS support.
        """
        routes = [
            Route(
                ServerMetadataPaths.OAUTH.value,
                self._create_metadata_endpoint(),
                methods=["GET", "OPTIONS"],
            )
        ]
        return Router(routes=routes)

    def _create_metadata_endpoint(self) -> Callable[[Request], Any]:
        """
        Returns a Starlette endpoint function that handles the OAuth 2.0 Authorization Metadata
        endpoint (`/.well-known/oauth-authorization-server`) with CORS support.
        """

        def endpoint(request: Request) -> Response:
            if request.method == "OPTIONS":
                response = Response(status_code=204)
            else:
                response = JSONResponse(
                    self.server.metadata.model_dump(exclude_none=True),
                    status_code=200,
                )
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            return response

        return endpoint

    def get_token_verifier(self, resource: str) -> TokenVerifier:
        """
        This is a dummy implementation that ignores the resource, as there is only
        one `TokenVerifier` in the authorization server mode.
        """
        return self.token_verifier 
