# MCP Auth sample servers

This sample server folder contains sample servers that demonstrate how to use the MCP Auth Python SDK in various scenarios.

See [the documentation](https://mcp-auth.dev/docs) for the full guide.

## Prerequisites

### Install dependencies

First, install the required dependencies:

```bash
# Install production dependencies
pip install -e .

# Install development dependencies (optional, for development and testing)
pip install -e ".[dev]"
```

### Environment setup

Set up the required environment variable:

```bash
# Set the auth issuer URL
export MCP_AUTH_ISSUER=<your_auth_issuer_url>
```

## Directory Structure

- `current/`: Latest sample implementations (MCP server as resource server)
- `v0_1_1/`: Legacy sample implementations (MCP server as authorization server)

## Get started

### Todo Manager MCP server (current)

The primary example demonstrating how to implement an MCP server as a resource server. This server validates tokens issued by an external authorization server and provides the following tools with scope-based access control:

- `create-todo`: Create a new todo (requires `create:todos` scope)
- `get-todos`: List todos (requires `read:todos` scope for all todos)
- `delete-todo`: Delete a todo (requires `delete:todos` scope for others' todos)

To run the Todo Manager server:

```bash
# Make sure you are in the samples directory first
cd samples

# Start the Todo Manager server
uvicorn current.todo-manager.server:app --host 0.0.0.0 --port 3001
```

## Legacy examples (v0.1.1)

These examples demonstrate the legacy approach where the MCP server acts as an authorization server.

### WhoAmI MCP server (legacy)

A simple server that demonstrates basic authentication. It provides a single tool:

- `whoami`: Returns the authenticated user's information

To run the WhoAmI server:
```bash
# Make sure you are in the samples directory first
cd samples

# Start the WhoAmI server
uvicorn v0_1_1.whoami:app --host 0.0.0.0 --port 3001
```

### Todo Manager MCP server (legacy)

Legacy version of the todo manager that acts as both authorization and resource server. It provides the following tools:

- `create-todo`: Create a new todo (requires `create:todos` scope)
- `get-todos`: List todos (requires `read:todos` scope for all todos)
- `delete-todo`: Delete a todo (requires `delete:todos` scope for others' todos)

To run the legacy Todo Manager server:
```bash
# Make sure you are in the samples directory first
cd samples

# Start the legacy Todo Manager server
uvicorn v0_1_1.todo-manager.server:app --host 0.0.0.0 --port 3001
```
