from enum import Enum
from pydantic import BaseModel
from typing import Any, Optional, List, Dict, Union

Record = Dict[str, Any]


class MCPAuthError(Exception):
    """
    Base class for all mcp-auth errors.
    This class provides a standardized way to handle errors related to MCP authentication and authorization.
    """

    def __init__(self, code: str, message: str, cause: Optional[Record] = None):
        """
        :param code: A unique error code in snake_case format that identifies the type of error.
        :param message: A human-readable description of the error.
        """

        self.code = code
        self.message = message
        self.cause = cause
        super().__init__(message)

    def to_json(self, show_cause: bool = False) -> Record:
        """
        Converts the error to a HTTP response friendly JSON format.

        :param show_cause: Whether to include the cause of the error in the JSON response. Defaults to `false`.
        """
        return {
            "error": self.code,
            "error_description": self.message,
            "cause": self.cause if show_cause and hasattr(self, "cause") else None,
        }


class MCPAuthConfigError(MCPAuthError):
    """
    Error thrown when there is a configuration issue with mcp-auth.
    """


class AuthServerErrorCode(str, Enum):
    INVALID_SERVER_METADATA = "invalid_server_metadata"
    INVALID_SERVER_CONFIG = "invalid_server_config"
    MISSING_JWKS_URI = "missing_jwks_uri"


auth_server_error_description: Dict[AuthServerErrorCode, str] = {
    AuthServerErrorCode.INVALID_SERVER_METADATA: "The server metadata is invalid or malformed.",
    AuthServerErrorCode.INVALID_SERVER_CONFIG: "The server configuration does not match the MCP specification.",
    AuthServerErrorCode.MISSING_JWKS_URI: "The server metadata does not contain a JWKS URI, which is required for JWT verification.",
}


class MCPAuthAuthServerError(MCPAuthError):
    """
    Error thrown when there is an issue with the remote authorization server.
    """

    def __init__(self, code: AuthServerErrorCode, cause: Optional[Record] = None):
        super().__init__(
            code.value,
            auth_server_error_description.get(
                code, "An error occurred with the authorization server."
            ),
        )
        self.code = code
        self.cause = cause


class BearerAuthErrorCode(str, Enum):
    MISSING_AUTH_HEADER = "missing_auth_header"
    INVALID_AUTH_HEADER_FORMAT = "invalid_auth_header_format"
    MISSING_BEARER_TOKEN = "missing_bearer_token"
    INVALID_ISSUER = "invalid_issuer"
    INVALID_AUDIENCE = "invalid_audience"
    MISSING_REQUIRED_SCOPES = "missing_required_scopes"
    INVALID_TOKEN = "invalid_token"


bearer_auth_error_description: Dict[BearerAuthErrorCode, str] = {
    BearerAuthErrorCode.MISSING_AUTH_HEADER: "Missing `Authorization` header. Please provide a valid bearer token.",
    BearerAuthErrorCode.INVALID_AUTH_HEADER_FORMAT: 'Invalid `Authorization` header format. Expected "Bearer <token>".',
    BearerAuthErrorCode.MISSING_BEARER_TOKEN: "Missing bearer token in `Authorization` header. Please provide a valid token.",
    BearerAuthErrorCode.INVALID_ISSUER: "The token issuer does not match the expected issuer.",
    BearerAuthErrorCode.INVALID_AUDIENCE: "The token audience does not match the expected audience.",
    BearerAuthErrorCode.MISSING_REQUIRED_SCOPES: "The token does not contain the necessary scopes for this request.",
    BearerAuthErrorCode.INVALID_TOKEN: "The provided token is not valid or has expired.",
}


class MCPAuthBearerAuthErrorDetails(BaseModel):
    cause: Optional[Record] = None
    uri: Optional[str] = None
    missing_scopes: Optional[List[str]] = None
    expected: Optional[Union[str, Record]] = None
    actual: Optional[Union[str, Record]] = None


class MCPAuthBearerAuthError(MCPAuthError):
    """
    Error thrown when there is an issue when authenticating with Bearer tokens.
    """

    def __init__(
        self,
        code: BearerAuthErrorCode,
        cause: Optional[MCPAuthBearerAuthErrorDetails] = None,
    ):
        super().__init__(
            code.value,
            bearer_auth_error_description.get(
                code, "An error occurred with the Bearer auth."
            ),
        )
        self.code = code
        self.cause = cause

    def to_json(self, show_cause: bool = False) -> Dict[str, Optional[str]]:
        # Matches the OAuth 2.0 error response format at best effort
        result = super().to_json(show_cause)
        if self.cause:
            result.update(
                {
                    "error_uri": self.cause.uri,
                    "missing_scopes": self.cause.missing_scopes,
                }
            )
        return result


class MCPAuthJwtVerificationErrorCode(str, Enum):
    INVALID_JWT = "invalid_jwt"
    JWT_VERIFICATION_FAILED = "jwt_verification_failed"
    JWT_EXPIRED = "jwt_expired"


jwt_verification_error_description: Dict[MCPAuthJwtVerificationErrorCode, str] = {
    MCPAuthJwtVerificationErrorCode.INVALID_JWT: "The provided JWT is invalid or malformed.",
    MCPAuthJwtVerificationErrorCode.JWT_VERIFICATION_FAILED: "JWT verification failed. The token could not be verified.",
    MCPAuthJwtVerificationErrorCode.JWT_EXPIRED: "The provided JWT has expired.",
}


class MCPAuthJwtVerificationError(MCPAuthError):
    """
    Error thrown when there is an issue when verifying JWT tokens.
    """

    def __init__(
        self, code: MCPAuthJwtVerificationErrorCode, cause: Optional[Record] = None
    ):
        super().__init__(
            code.value,
            jwt_verification_error_description.get(
                code, "An error occurred while verifying the JWT."
            ),
        )
        self.code = code
        self.cause = cause
