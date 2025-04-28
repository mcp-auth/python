from .errors import (
    MCPAuthError as MCPAuthError,
    MCPAuthConfigError as MCPAuthConfigError,
    AuthServerErrorCode as AuthServerErrorCode,
    MCPAuthAuthServerError as MCPAuthAuthServerError,
    BearerAuthErrorCode as BearerAuthErrorCode,
    MCPAuthBearerAuthErrorDetails as MCPAuthBearerAuthErrorDetails,
    MCPAuthBearerAuthError as MCPAuthBearerAuthError,
    MCPAuthJwtVerificationErrorCode as MCPAuthJwtVerificationErrorCode,
    MCPAuthJwtVerificationError as MCPAuthJwtVerificationError,
)


class MCPAuth:
    def __init__(self):
        self.config = None
