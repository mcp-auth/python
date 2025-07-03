from typing import Dict, List, Union
from urllib.parse import urlparse

from starlette.routing import Route, Router
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..exceptions import AuthServerExceptionCode, MCPAuthAuthServerException
from ..types import ResourceServerConfig
from ..config import ProtectedResourceMetadata
from ..utils import (
    create_resource_metadata_endpoint,
    transpile_resource_metadata,
    validate_server_config,
)
from .mcp_auth_handler import MCPAuthHandler
from .token_verifier import TokenVerifier


class ResourceServerModeConfig:
    """
    Configuration for the MCP-server-as-resource-server mode.
    """

    def __init__(
        self,
        protected_resources: Union[ResourceServerConfig, List[ResourceServerConfig]],
    ):
        self.protected_resources = protected_resources


class ResourceServerHandler(MCPAuthHandler):
    """
    Handles the authentication logic for the MCP server as resource server mode.
    """

    _token_verifiers: Dict[str, TokenVerifier]
    _resources_configs: List[ResourceServerConfig]

    def __init__(self, config: ResourceServerModeConfig):
        self._resources_configs = self._get_resources_configs(config)
        self._validate_config(self._resources_configs)

        self._token_verifiers = {}
        for resource_config in self._resources_configs:
            resource = resource_config.metadata.resource
            auth_servers = resource_config.metadata.authorization_servers or []
            self._token_verifiers[resource] = TokenVerifier(auth_servers)

    def create_metadata_route(self) -> Router:
        routes: List[Route] = []
        for resource_config in self._resources_configs:
            metadata = transpile_resource_metadata(resource_config.metadata)
            endpoint_path = create_resource_metadata_endpoint(metadata.resource)

            def endpoint(
                request: Request, _metadata: ProtectedResourceMetadata = metadata
            ) -> Response:
                if request.method == "OPTIONS":
                    response = Response(status_code=204)
                else:
                    response = JSONResponse(_metadata.model_dump(exclude_none=True))
                response.headers["Access-Control-Allow-Origin"] = "*"
                response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "*"
                return response

            routes.append(
                Route(
                    urlparse(endpoint_path).path,
                    endpoint=endpoint,
                    methods=["GET", "OPTIONS"],
                )
            )
        return Router(routes=routes)

    def get_token_verifier(self, resource: str) -> TokenVerifier:
        verifier = self._token_verifiers.get(resource)

        if not verifier:
            raise MCPAuthAuthServerException(
                AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                cause={
                    "error_description": f"No token verifier found for the specified resource: `{resource}`. Please ensure that this resource is correctly configured in the `protectedResources` array in the MCPAuth constructor."
                },
            )

        return verifier

    def _get_resources_configs(
        self, config: ResourceServerModeConfig
    ) -> List[ResourceServerConfig]:
        if isinstance(config.protected_resources, list):
            return config.protected_resources
        return [config.protected_resources]

    def _validate_config(self, resource_configs: List[ResourceServerConfig]):
        unique_resources: set[str] = set()

        for resource_config in resource_configs:
            resource = resource_config.metadata.resource
            if resource in unique_resources:
                raise MCPAuthAuthServerException(
                    AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                    cause={"error_description": f"The resource metadata ('{resource}') is duplicated."},
                )
            unique_resources.add(resource)

            unique_auth_servers: set[str] = set()
            if resource_config.metadata.authorization_servers:
                for auth_server in resource_config.metadata.authorization_servers:
                    issuer = auth_server.metadata.issuer
                    if issuer in unique_auth_servers:
                        raise MCPAuthAuthServerException(
                            AuthServerExceptionCode.INVALID_SERVER_CONFIG,
                            cause={"error_description": f"The authorization server ('{issuer}') for resource '{resource}' is duplicated."},
                        )
                    unique_auth_servers.add(issuer)
                    validate_server_config(auth_server) 
