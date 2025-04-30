import logging

from .utils.fetch_server_config import ServerMetadataPaths
from .config import MCPAuthConfig
from .exceptions import MCPAuthAuthServerException, AuthServerExceptionCode
from .utils.validate_server_config import validate_server_config
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse


class MCPAuth:
    def __init__(self, config: MCPAuthConfig):
        result = validate_server_config(config.server)

        if not result.is_valid:
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG, cause=result
            )

        if len(result.warnings) > 0:
            logging.warning("The authorization server configuration has warnings:\n")
            for warning in result.warnings:
                logging.warning(f"- {warning}")

        self.config = config

    def delegated_middleware(self) -> type[BaseHTTPMiddleware]:
        """
        Returns a middleware that handles OAuth 2.0 Authorization Metadata endpoint
        (`/.well-known/oauth-authorization-server`) with CORS support (delegated mode).

        :return: A middleware class that can be used in a Starlette or FastAPI application.
        """
        server_config = self.config.server

        class DelegatedMiddleware(BaseHTTPMiddleware):
            async def dispatch(
                self, request: Request, call_next: RequestResponseEndpoint
            ) -> Response:
                path = request.url.path
                if path == ServerMetadataPaths.OAUTH:
                    response = JSONResponse(
                        {
                            k: v
                            for k, v in server_config.metadata.model_dump().items()
                            if v is not None
                        },
                        status_code=200,
                    )
                    response.headers["Access-Control-Allow-Origin"] = "*"
                    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                    return response
                else:
                    return await call_next(request)

        return DelegatedMiddleware
