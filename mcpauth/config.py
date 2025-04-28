from .models.auth_server import AuthServerConfig
from pydantic import BaseModel


class MCPAuthConfig(BaseModel):
    """
    Configuration for the `MCPAuth` class.
    """

    server: AuthServerConfig
    """
    Config for the remote authorization server.
    """
