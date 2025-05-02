from typing import Annotated, List, Optional, Union
from jwt import PyJWK, PyJWKClient, PyJWTError, decode
from pydantic import BaseModel, StringConstraints, ValidationError
from ..types import AuthInfo, VerifyAccessTokenFunction
from ..exceptions import (
    MCPAuthJwtVerificationException,
    MCPAuthJwtVerificationExceptionCode,
)

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]


class JwtBaseModel(BaseModel):
    aud: Optional[Union[NonEmptyString, List[NonEmptyString]]] = None
    iss: NonEmptyString
    client_id: NonEmptyString
    sub: NonEmptyString
    scope: Optional[Union[str, List[str]]] = None
    scopes: Optional[Union[str, List[str]]] = None
    exp: Optional[int] = None


def create_verify_jwt(
    input: Union[str, PyJWKClient, PyJWK],
    algorithms: List[str] = ["RS256", "PS256", "ES256", "ES384", "ES512"],
    leeway: float = 60,
) -> VerifyAccessTokenFunction:
    """
    Creates a JWT verification function using the provided JWKS URI.

    :param input: Supports one of the following:
        - A JWKS URI (string) that points to a JSON Web Key Set.
        - An instance of `PyJWKClient` that has been initialized with the JWKS URI.
        - An instance of `PyJWK` that represents a single JWK.
    :param algorithms: A list of acceptable algorithms for verifying the JWT signature.
    :param leeway: The amount of leeway (in seconds) to allow when checking the expiration time of the JWT.
    :return: A function that can be used to verify JWTs.
    """

    jwks = (
        input
        if isinstance(input, PyJWKClient)
        else (
            PyJWKClient(
                input, headers={"user-agent": "@mcp-auth/python", "accept": "*/*"}
            )
            if isinstance(input, str)
            else input
        )
    )

    def verify_jwt(token: str) -> AuthInfo:
        try:
            signing_key = (
                jwks.get_signing_key_from_jwt(token)
                if isinstance(jwks, PyJWKClient)
                else jwks
            )
            decoded = decode(
                token,
                signing_key.key,
                algorithms=algorithms,
                leeway=leeway,
                options={
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
            base_model = JwtBaseModel(**decoded)
            scopes = base_model.scope or base_model.scopes
            return AuthInfo(
                token=token,
                issuer=base_model.iss,
                client_id=base_model.client_id,
                subject=base_model.sub,
                audience=base_model.aud,
                scopes=(scopes.split(" ") if isinstance(scopes, str) else scopes) or [],
                expires_at=base_model.exp,
                claims=decoded,
            )
        except (PyJWTError, ValidationError) as e:
            raise MCPAuthJwtVerificationException(
                MCPAuthJwtVerificationExceptionCode.INVALID_JWT,
                cause=e,
            )
        except Exception as e:
            raise MCPAuthJwtVerificationException(
                MCPAuthJwtVerificationExceptionCode.JWT_VERIFICATION_FAILED,
                cause=e,
            )

    return verify_jwt
