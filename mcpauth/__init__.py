from .exceptions import (
    MCPAuthException as MCPAuthException,
    MCPAuthConfigException as MCPAuthConfigException,
    AuthServerExceptionCode as AuthServerExceptionCode,
    MCPAuthAuthServerException as MCPAuthAuthServerException,
    BearerAuthExceptionCode as BearerAuthExceptionCode,
    MCPAuthBearerAuthExceptionDetails as MCPAuthBearerAuthExceptionDetails,
    MCPAuthBearerAuthException as MCPAuthBearerAuthException,
    MCPAuthJwtVerificationExceptionCode as MCPAuthJwtVerificationExceptionCode,
    MCPAuthJwtVerificationException as MCPAuthJwtVerificationException,
)


class MCPAuth:
    def __init__(self):
        self.config = None
