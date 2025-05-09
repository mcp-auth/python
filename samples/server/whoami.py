"""
An FastMCP server that provides a "WhoAmI" tool to return the current user's information.

This server is compatible with OpenID Connect (OIDC) providers and uses the `mcpauth` library
to handle authorization. Please check https://mcp-auth.dev/docs/tutorials/whoami for more
information on how to use this server.
"""

import os
from typing import Any
from mcp.server.fastmcp import FastMCP
import pydantic
import requests
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.middleware import Middleware


from mcpauth import MCPAuth
from mcpauth.config import AuthServerType
from mcpauth.exceptions import (
    MCPAuthTokenVerificationException,
    MCPAuthTokenVerificationExceptionCode,
)
from mcpauth.types import AuthInfo
from mcpauth.utils import fetch_server_config

mcp = FastMCP("WhoAmI")
issuer_placeholder = "https://replace-with-your-issuer-url.com"
auth_issuer = os.getenv("MCP_AUTH_ISSUER", issuer_placeholder)

if auth_issuer == issuer_placeholder:
    raise ValueError(
        f"MCP_AUTH_ISSUER environment variable is not set. Please set it to your authorization server's issuer URL."
    )

auth_server_config = fetch_server_config(auth_issuer, AuthServerType.OIDC)
mcp_auth = MCPAuth(server=auth_server_config)


@mcp.tool()
def whoami() -> dict[str, Any]:
    """A tool that returns the current user's information."""
    return (
        mcp_auth.auth_info.claims
        if mcp_auth.auth_info
        else {"error": "Not authenticated"}
    )


def verify_access_token(token: str) -> AuthInfo:
    """
    Verifies the provided Bearer token by fetching user information from the authorization server.
    If the token is valid, it returns an `AuthInfo` object containing the user's information.
    """

    issuer = auth_server_config.metadata.issuer
    endpoint = auth_server_config.metadata.userinfo_endpoint
    if not endpoint:
        raise ValueError(
            "Userinfo endpoint is not configured in the auth server metadata."
        )

    try:
        response = requests.get(
            endpoint,
            headers={
                "Authorization": f"Bearer {token}"
            },  # Standard Bearer token header
        )
        response.raise_for_status()  # Ensure we raise an error for HTTP errors
        json = response.json()  # Parse the JSON response
        return AuthInfo(
            token=token,
            subject=json.get(
                "sub"
            ),  # 'sub' is a standard claim for the subject (user's ID)
            issuer=issuer,  # Use the issuer from the metadata
            claims=json,  # Include all claims (JSON fields) returned by the userinfo endpoint
        )
    # `AuthInfo` is a Pydantic model, so validation errors usually mean the response didn't match
    # the expected structure
    except pydantic.ValidationError as e:
        raise MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN,
            cause=e,
        )
    # Handle other exceptions that may occur during the request
    except Exception as e:
        raise MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.TOKEN_VERIFICATION_FAILED,
            cause=e,
        )


bearer_auth = Middleware(mcp_auth.bearer_auth_middleware(verify_access_token))
app = Starlette(
    routes=[
        # Add the metadata route (`/.well-known/oauth-authorization-server`)
        mcp_auth.metadata_route(),
        # Protect the MCP server with the Bearer auth middleware
        Mount("/", app=mcp.sse_app(), middleware=[bearer_auth]),
    ],
)
