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
    endpoint = auth_server_config.metadata.userinfo_endpoint
    if not endpoint:
        raise ValueError(
            "Userinfo endpoint is not configured in the auth server metadata."
        )

    try:
        response = requests.get(
            endpoint,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        json = response.json()
        return AuthInfo(
            token=token,
            subject=json.get("sub"),
            issuer=auth_issuer,
            claims=json,
        )
    except pydantic.ValidationError as e:
        raise MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN,
            cause=e,
        )
    except Exception as e:
        raise MCPAuthTokenVerificationException(
            MCPAuthTokenVerificationExceptionCode.TOKEN_VERIFICATION_FAILED,
            cause=e,
        )


app = Starlette(
    routes=[
        mcp_auth.metadata_route(),
        Mount(
            "/",
            app=mcp.sse_app(),
            middleware=[
                Middleware(mcp_auth.bearer_auth_middleware(verify_access_token))
            ],
        ),
    ]
)
