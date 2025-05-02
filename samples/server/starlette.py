from mcpauth import MCPAuth
from mcpauth.config import MCPAuthConfig
from mcpauth.models import AuthServerType
from mcpauth.utils import fetch_server_config, ServerMetadataPaths
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.requests import Request
import os

MCP_AUTH_ISSUER = (
    os.getenv("MCP_AUTH_ISSUER") or "https://replace-with-your-issuer-url.com"
)

mcpAuth = MCPAuth(
    MCPAuthConfig(server=fetch_server_config(MCP_AUTH_ISSUER, AuthServerType.OIDC))
)

protected_app = Starlette(
    middleware=[Middleware(mcpAuth.bearer_auth_middleware("jwt"))]
)


@protected_app.route("/")  # type: ignore
async def secret_endpoint(_: Request):
    return JSONResponse({"secret": True})


app = Starlette(
    debug=True,
)
app.mount(ServerMetadataPaths.OAUTH.value, mcpAuth.metadata_response())
app.mount("/mcp", protected_app)
