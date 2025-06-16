"""
An FastMCP server that provides Todo management tools with authentication and authorization.

This server demonstrates more complex authentication scenarios with different permission scopes:
- create-todo: Create a new todo (requires 'create:todos' scope)
- get-todos: List todos (requires 'read:todos' scope for all todos, otherwise only own todos)
- delete-todo: Delete a todo (requires 'delete:todos' scope for others' todos)

This server is compatible with OpenID Connect (OIDC) providers and uses the `mcpauth` library
to handle authorization. Please check https://mcp-auth.dev/docs/tutorials/todo-manager for more
information on how to use this server.
"""

import os
from typing import Any, List, Optional
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.middleware import Middleware

from mcpauth import MCPAuth
from mcpauth.config import AuthServerType
from mcpauth.exceptions import (
    MCPAuthBearerAuthException,
    BearerAuthExceptionCode,
)
from mcpauth.types import AuthInfo
from mcpauth.utils import fetch_server_config
from .service import TodoService

# Initialize the FastMCP server
mcp = FastMCP("Todo Manager")

# Initialize the todo service
todo_service = TodoService()

# Authorization server configuration
issuer_placeholder = "https://replace-with-your-issuer-url.com"
auth_issuer = os.getenv("MCP_AUTH_ISSUER", issuer_placeholder)

if auth_issuer == issuer_placeholder:
    raise ValueError(
        "MCP_AUTH_ISSUER environment variable is not set. Please set it to your authorization server's issuer URL."
    )

auth_server_config = fetch_server_config(auth_issuer, AuthServerType.OIDC)
mcp_auth = MCPAuth(server=auth_server_config)

def assert_user_id(auth_info: Optional[AuthInfo]) -> str:
    """Assert that auth_info contains a valid user ID and return it."""
    if not auth_info or not auth_info.subject:
        raise Exception("Invalid auth info")
    return auth_info.subject


def has_required_scopes(user_scopes: List[str], required_scopes: List[str]) -> bool:
    """Check if user has all required scopes."""
    return all(scope in user_scopes for scope in required_scopes)


@mcp.tool()
def create_todo(content: str) -> dict[str, Any]:
    """Create a new todo. Requires 'create:todos' scope."""
    auth_info = mcp_auth.auth_info
    user_id = assert_user_id(auth_info)
    
    # Only users with 'create:todos' scope can create todos
    user_scopes = auth_info.scopes if auth_info else []
    if not has_required_scopes(user_scopes, ["create:todos"]):
        raise MCPAuthBearerAuthException(BearerAuthExceptionCode.MISSING_REQUIRED_SCOPES)
    
    created_todo = todo_service.create_todo(content=content, owner_id=user_id)
    return created_todo


@mcp.tool()
def get_todos() -> dict[str, Any]:
    """
    List todos. Users with 'read:todos' scope can see all todos,
    otherwise they can only see their own todos.
    """
    auth_info = mcp_auth.auth_info
    user_id = assert_user_id(auth_info)
    
    # If user has 'read:todos' scope, they can access all todos
    # If user doesn't have 'read:todos' scope, they can only access their own todos
    user_scopes = auth_info.scopes if auth_info else []
    todo_owner_id = None if has_required_scopes(user_scopes, ["read:todos"]) else user_id
    
    todos = todo_service.get_all_todos(todo_owner_id)
    return {"todos": todos}


@mcp.tool()
def delete_todo(id: str) -> dict[str, Any]:
    """
    Delete a todo by id. Users can delete their own todos.
    Users with 'delete:todos' scope can delete any todo.
    """
    auth_info = mcp_auth.auth_info
    user_id = assert_user_id(auth_info)
    
    todo = todo_service.get_todo_by_id(id)
    
    if not todo:
        return {"error": "Failed to delete todo"}
    
    # Users can only delete their own todos
    # Users with 'delete:todos' scope can delete any todo
    user_scopes = auth_info.scopes if auth_info else []
    if todo.owner_id != user_id and not has_required_scopes(user_scopes, ["delete:todos"]):
        return {"error": "Failed to delete todo"}
    
    deleted_todo = todo_service.delete_todo(id)
    
    if deleted_todo:
        return {
            "message": f"Todo {id} deleted",
            "details": deleted_todo
        }
    else:
        return {"error": "Failed to delete todo"}

# Create the middleware and app
bearer_auth = Middleware(mcp_auth.bearer_auth_middleware('jwt'))
app = Starlette(
    routes=[
        # Add the metadata route (`/.well-known/oauth-authorization-server`)
        mcp_auth.metadata_route(), # pyright: ignore[reportDeprecated]
        # Protect the MCP server with the Bearer auth middleware
        Mount("/", app=mcp.sse_app(), middleware=[bearer_auth]),
    ],
) 
