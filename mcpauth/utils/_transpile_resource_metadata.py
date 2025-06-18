from typing import List, Optional

from ..config import ProtectedResourceMetadata
from ..types import ResourceServerMetadata


def transpile_resource_metadata(
    metadata: ResourceServerMetadata,
) -> ProtectedResourceMetadata:
    """
    Transforms protected resource metadata from MCPAuth config format to the standard
    OAuth 2.0 Protected Resource Metadata format.

    The main transformation is converting the authorization servers from AuthServerConfig
    objects to their issuer URLs. This is needed because the OAuth 2.0 Protected
    Resource Metadata specification expects authorization servers to be represented as
    issuer URL strings, while MCP Auth internally uses `AuthServerConfig` objects to
    store the complete authorization server metadata for token validation and issuer
    verification.
    """
    # Use model_dump to get other fields, excluding authorization_servers for custom handling.
    model_data = metadata.model_dump(exclude={"authorization_servers"}, exclude_none=True)

    auth_servers: Optional[List[str]] = None
    if metadata.authorization_servers:
        auth_servers = [
            server.metadata.issuer for server in metadata.authorization_servers
        ]

    # Only add authorization_servers to the dict if it's not None (and not empty)
    if auth_servers:
        model_data["authorization_servers"] = auth_servers

    return ProtectedResourceMetadata(**model_data) 
