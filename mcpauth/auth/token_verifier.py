from typing import List

import jwt
from ..config import AuthServerConfig
from ..exceptions import (
    AuthServerExceptionCode,
    BearerAuthExceptionCode,
    MCPAuthAuthServerException,
    MCPAuthBearerAuthException,
    MCPAuthTokenVerificationException,
    MCPAuthTokenVerificationExceptionCode,
)
from ..types import AuthInfo, VerifyAccessTokenFunction
from ..utils import create_verify_jwt


class TokenVerifier:
    """
    Encapsulates all authentication logic and policies for a specific protected resource
    or a legacy `server` configuration.
    """

    def __init__(self, auth_servers: List[AuthServerConfig]):
        self._auth_servers = auth_servers
        self._issuers = {server.metadata.issuer for server in auth_servers}

    def _get_unverified_jwt_issuer(self, token: str) -> str:
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as e:
            raise MCPAuthTokenVerificationException(
                MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN,
                cause={"error_description": "The JWT is malformed or invalid.", "cause": e},
            )

        issuer = payload.get("iss")
        if not issuer or not isinstance(issuer, str):
            raise MCPAuthTokenVerificationException(
                MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN,
                cause={
                    "error_description": "The JWT payload does not contain the `iss` field."
                },
            )
        return issuer

    def _get_auth_server_by_issuer(self, issuer: str) -> AuthServerConfig:
        for server in self._auth_servers:
            if server.metadata.issuer == issuer:
                return server
        raise MCPAuthBearerAuthException(
            BearerAuthExceptionCode.INVALID_ISSUER,
        )

    def validate_jwt_issuer(self, issuer: str):
        if issuer not in self._issuers:
            # The cause of MCPAuthBearerAuthException is MCPAuthBearerAuthExceptionDetails,
            # which is a BaseModel. We need to create it.
            from ..exceptions import MCPAuthBearerAuthExceptionDetails

            raise MCPAuthBearerAuthException(
                BearerAuthExceptionCode.INVALID_ISSUER,
                cause=MCPAuthBearerAuthExceptionDetails(
                    expected=", ".join(self._issuers), actual=issuer
                ),
            )

    def create_verify_jwt_function(
        self, leeway: float = 60
    ) -> VerifyAccessTokenFunction:
        def verify_jwt(token: str) -> AuthInfo:
            unverified_issuer = self._get_unverified_jwt_issuer(token)
            self.validate_jwt_issuer(unverified_issuer)

            auth_server = self._get_auth_server_by_issuer(unverified_issuer)
            jwks_uri = auth_server.metadata.jwks_uri

            if not jwks_uri:
                raise MCPAuthAuthServerException(
                    AuthServerExceptionCode.MISSING_JWKS_URI,
                    cause={
                        "error_description": f"The authorization server ('{unverified_issuer}') does not have a JWKS URI configured."
                    },
                )

            verify_function = create_verify_jwt(jwks_uri, leeway=leeway)
            return verify_function(token)

        return verify_jwt 
