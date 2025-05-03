from unittest.mock import MagicMock
import pytest
import time
import jwt
import base64
from typing import Dict, Any
from mcpauth.utils import create_verify_jwt
from mcpauth.types import AuthInfo


from mcpauth.exceptions import (
    MCPAuthTokenVerificationException,
    MCPAuthTokenVerificationExceptionCode,
)

_secret_key = b"super-secret-key-for-testing"
_algorithm = "HS256"


def create_jwk(key: bytes = _secret_key) -> jwt.PyJWK:
    """Create a JWK for testing purposes"""
    return jwt.PyJWK(
        {
            "kty": "oct",
            "k": base64.urlsafe_b64encode(key).decode("utf-8"),
            "alg": _algorithm,
        }
    )


def create_jwt(payload: Dict[str, Any]) -> str:
    """Create a test JWT with the given payload"""
    return jwt.encode(
        {
            **payload,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # 1 hour
        },
        _secret_key,
        algorithm=_algorithm,
    )


verify_jwt = create_verify_jwt(create_jwk(), algorithms=[_algorithm])


class TestCreateVerifyJwtErrorHandling:
    def test_should_throw_error_if_signature_verification_fails(self):
        # Create JWT with correct secret
        jwt_token = create_jwt({"client_id": "client12345", "sub": "user12345"})
        verify_jwt = create_verify_jwt(
            create_jwk(b"wrong-secret-key-for-testing"), algorithms=[_algorithm]
        )

        # Verify that the correct exception is raised
        with pytest.raises(MCPAuthTokenVerificationException) as exc_info:
            verify_jwt(jwt_token)

        assert (
            exc_info.value.code == MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
        )
        assert isinstance(exc_info.value.cause, jwt.InvalidSignatureError)

    def test_should_throw_error_if_jwt_payload_missing_iss(self):
        # Test different invalid JWT payloads
        jwt_missing_iss = create_jwt({"client_id": "client12345", "sub": "user12345"})
        jwt_invalid_iss_type = create_jwt(
            {"iss": 12345, "client_id": "client12345", "sub": "user12345"}
        )
        jwt_empty_iss = create_jwt(
            {"iss": "", "client_id": "client12345", "sub": "user12345"}
        )

        for token in [jwt_missing_iss, jwt_invalid_iss_type, jwt_empty_iss]:
            with pytest.raises(MCPAuthTokenVerificationException) as exc_info:
                verify_jwt(token)
            assert (
                exc_info.value.code
                == MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
            )

    def test_should_throw_error_if_jwt_payload_missing_client_id(self):
        # Test different invalid JWT payloads
        jwt_missing_client_id = create_jwt(
            {"iss": "https://logto.io/", "sub": "user12345"}
        )
        jwt_invalid_client_id_type = create_jwt(
            {"iss": "https://logto.io/", "client_id": 12345, "sub": "user12345"}
        )
        jwt_empty_client_id = create_jwt(
            {"iss": "https://logto.io/", "client_id": "", "sub": "user12345"}
        )

        for token in [
            jwt_missing_client_id,
            jwt_invalid_client_id_type,
            jwt_empty_client_id,
        ]:
            with pytest.raises(MCPAuthTokenVerificationException) as exc_info:
                verify_jwt(token)
            assert (
                exc_info.value.code
                == MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
            )

    def test_should_throw_error_if_jwt_payload_missing_sub(self):
        # Test different invalid JWT payloads
        jwt_missing_sub = create_jwt(
            {"iss": "https://logto.io/", "client_id": "client12345"}
        )
        jwt_invalid_sub_type = create_jwt(
            {"iss": "https://logto.io/", "client_id": "client12345", "sub": 12345}
        )
        jwt_empty_sub = create_jwt(
            {"iss": "https://logto.io/", "client_id": "client12345", "sub": ""}
        )

        for token in [jwt_missing_sub, jwt_invalid_sub_type, jwt_empty_sub]:
            with pytest.raises(MCPAuthTokenVerificationException) as exc_info:
                verify_jwt(token)
            assert (
                exc_info.value.code
                == MCPAuthTokenVerificationExceptionCode.INVALID_TOKEN
            )

    def test_should_throw_error_if_unknown_exception_occurs(self):
        # Mock get_signing_key_from_jwt to raise an unexpected exception
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.side_effect = Exception(
            "Unexpected error"
        )
        verify_jwt = create_verify_jwt(mock_jwk_client, algorithms=[_algorithm])
        jwt_token = create_jwt(
            {"iss": "https://logto.io/", "client_id": "client12345", "sub": "user12345"}
        )

        # Verify that the correct exception is raised
        with pytest.raises(MCPAuthTokenVerificationException) as exc_info:
            verify_jwt(jwt_token)
        assert (
            exc_info.value.code
            == MCPAuthTokenVerificationExceptionCode.TOKEN_VERIFICATION_FAILED
        )


class TestCreateVerifyJwtNormalBehavior:
    def test_should_return_verified_jwt_payload_with_string_scope(self):
        # Create JWT with string scope
        claims = {
            "iss": "https://logto.io/",
            "client_id": "client12345",
            "sub": "user12345",
            "scope": "read write",
            "aud": "audience12345",
        }
        jwt_token = create_jwt(claims)

        # Verify
        result = verify_jwt(jwt_token)

        # Assertions
        assert isinstance(result, AuthInfo)
        assert result.token == jwt_token
        assert result.issuer == claims["iss"]
        assert result.client_id == claims["client_id"]
        assert result.subject == claims["sub"]
        assert result.audience == claims["aud"]
        assert result.scopes == ["read", "write"]
        assert "exp" in result.claims
        assert "iat" in result.claims

    def test_should_return_verified_jwt_payload_with_array_scope(self):
        # Create JWT with array scope
        claims: Dict[str, Any] = {
            "iss": "https://logto.io/",
            "client_id": "client12345",
            "sub": "user12345",
            "scope": ["read", "write"],
        }
        jwt_token = create_jwt(claims)

        # Verify
        result = verify_jwt(jwt_token)

        # Assertions
        assert result.issuer == claims["iss"]
        assert result.client_id == claims["client_id"]
        assert result.subject == claims["sub"]
        assert result.scopes == ["read", "write"]

    def test_should_return_verified_jwt_payload_with_scopes_field(self):
        # Create JWT with scopes field
        claims: Dict[str, Any] = {
            "iss": "https://logto.io/",
            "client_id": "client12345",
            "sub": "user12345",
            "scopes": ["read", "write"],
        }
        jwt_token = create_jwt(claims)

        # Verify
        result = verify_jwt(jwt_token)

        # Assertions
        assert result.issuer == claims["iss"]
        assert result.client_id == claims["client_id"]
        assert result.subject == claims["sub"]
        assert result.scopes == ["read", "write"]

    def test_should_return_verified_jwt_payload_without_scopes(self):
        # Create JWT without scope or scopes
        claims = {
            "iss": "https://logto.io/",
            "client_id": "client12345",
            "sub": "user12345",
            "aud": "audience12345",
        }
        jwt_token = create_jwt(claims)

        # Verify
        result = verify_jwt(jwt_token)

        # Assertions
        assert result.issuer == claims["iss"]
        assert result.client_id == claims["client_id"]
        assert result.subject == claims["sub"]
        assert result.audience == claims["aud"]
        assert result.scopes == []
