from mcpauth import MCPAuth
from mcpauth.config import AuthServerType, ServerMetadataPaths
from mcpauth.utils import fetch_server_config
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.routing import Route
import os

MCP_AUTH_ISSUER = (
    os.getenv("MCP_AUTH_ISSUER") or "https://replace-with-your-issuer-url.com"
)

mcp_auth = MCPAuth(server=fetch_server_config(MCP_AUTH_ISSUER, AuthServerType.OIDC))


async def mcp_endpoint(request: Request):
    return JSONResponse({"auth": request.state.auth})


protected_app = Starlette(
    middleware=[
        Middleware(mcp_auth.bearer_auth_middleware("jwt", required_scopes=["read"]))
    ],
    routes=[Route("/", endpoint=mcp_endpoint)],
)

app = Starlette(
    debug=True,
)
app.mount(ServerMetadataPaths.OAUTH.value, mcp_auth.metadata_response())
app.mount("/mcp", protected_app)
