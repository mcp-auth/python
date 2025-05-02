from mcpauth.config import AuthServerConfig, AuthServerType, AuthorizationServerMetadata
from mcpauth.utils import (
    validate_server_config,
    AuthServerConfigErrorCode,
    AuthServerConfigWarningCode,
)


class TestValidateServerConfig:
    def test_valid_server_config(self):
        config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
                registration_endpoint="https://example.com/register",
            ),
        )

        result = validate_server_config(config)
        assert result.is_valid is True
        assert not hasattr(result, "errors") or len(result.errors) == 0
        assert result.warnings == []

    def test_invalid_server_config(self):
        config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["token"],  # Invalid response type
            ),
        )

        result = validate_server_config(config)
        assert result.is_valid is False

        error_codes = [error.code for error in result.errors]
        assert AuthServerConfigErrorCode.CODE_RESPONSE_TYPE_NOT_SUPPORTED in error_codes
        assert (
            AuthServerConfigErrorCode.AUTHORIZATION_CODE_GRANT_NOT_SUPPORTED
            in error_codes
        )
        assert AuthServerConfigErrorCode.PKCE_NOT_SUPPORTED in error_codes

        warning_codes = [warning.code for warning in result.warnings]
        assert (
            AuthServerConfigWarningCode.DYNAMIC_REGISTRATION_NOT_SUPPORTED
            in warning_codes
        )

    def test_warning_for_missing_dynamic_registration(self):
        config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["S256"],
            ),
        )

        result = validate_server_config(config)
        assert result.is_valid is True
        assert not hasattr(result, "errors") or len(result.errors) == 0

        warning_codes = [warning.code for warning in result.warnings]
        assert (
            AuthServerConfigWarningCode.DYNAMIC_REGISTRATION_NOT_SUPPORTED
            in warning_codes
        )
        assert len(result.warnings) == 1

    def test_code_challenge_methods(self):
        config = AuthServerConfig(
            type=AuthServerType.OAUTH,
            metadata=AuthorizationServerMetadata(
                issuer="https://example.com",
                authorization_endpoint="https://example.com/oauth/authorize",
                token_endpoint="https://example.com/oauth/token",
                response_types_supported=["code"],
                grant_types_supported=["authorization_code"],
                code_challenge_methods_supported=["plain"],
            ),
        )

        result = validate_server_config(config)
        assert result.is_valid is False

        error_codes = [error.code for error in result.errors]
        assert (
            AuthServerConfigErrorCode.S256_CODE_CHALLENGE_METHOD_NOT_SUPPORTED
            in error_codes
        )
