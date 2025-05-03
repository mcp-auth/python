from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from ..config import AuthServerConfig


class AuthServerConfigErrorCode(str, Enum):
    """
    The codes for errors that can occur when validating the authorization server metadata.
    """

    INVALID_SERVER_METADATA = "invalid_server_metadata"
    CODE_RESPONSE_TYPE_NOT_SUPPORTED = "code_response_type_not_supported"
    AUTHORIZATION_CODE_GRANT_NOT_SUPPORTED = "authorization_code_grant_not_supported"
    PKCE_NOT_SUPPORTED = "pkce_not_supported"
    S256_CODE_CHALLENGE_METHOD_NOT_SUPPORTED = (
        "s256_code_challenge_method_not_supported"
    )


auth_server_config_error_description: Dict[AuthServerConfigErrorCode, str] = {
    AuthServerConfigErrorCode.INVALID_SERVER_METADATA: "The server metadata is not a valid object or does not conform to the expected schema.",
    AuthServerConfigErrorCode.CODE_RESPONSE_TYPE_NOT_SUPPORTED: 'The server does not support the "code" response type or the "code" response type is not included in one of the supported response types.',
    AuthServerConfigErrorCode.AUTHORIZATION_CODE_GRANT_NOT_SUPPORTED: 'The server does not support the "authorization_code" grant type.',
    AuthServerConfigErrorCode.PKCE_NOT_SUPPORTED: "The server does not support Proof Key for Code Exchange (PKCE).",
    AuthServerConfigErrorCode.S256_CODE_CHALLENGE_METHOD_NOT_SUPPORTED: 'The server does not support the "S256" code challenge method for Proof Key for Code Exchange (PKCE).',
}


class AuthServerConfigError(BaseModel):
    """
    Represents an error that occurs during the validation of the authorization server metadata.
    """

    code: AuthServerConfigErrorCode
    description: str
    cause: Any


def _create_error(
    code: AuthServerConfigErrorCode, cause: Optional[Exception] = None
) -> AuthServerConfigError:

    return AuthServerConfigError(
        code=code,
        description=auth_server_config_error_description[code],
        cause=cause,
    )


class AuthServerConfigWarningCode(str, Enum):
    """
    The codes for warnings that can occur when validating the authorization server metadata.
    """

    DYNAMIC_REGISTRATION_NOT_SUPPORTED = "dynamic_registration_not_supported"


auth_server_config_warning_description: Dict[AuthServerConfigWarningCode, str] = {
    AuthServerConfigWarningCode.DYNAMIC_REGISTRATION_NOT_SUPPORTED: "Dynamic Client Registration (RFC 7591) is not supported by the server."
}


class AuthServerConfigWarning(BaseModel):
    """
    Represents a warning that occurs during the validation of the authorization server metadata.
    """

    code: AuthServerConfigWarningCode
    description: str


def _create_warning(code: AuthServerConfigWarningCode) -> AuthServerConfigWarning:
    return AuthServerConfigWarning(
        code=code,
        description=auth_server_config_warning_description[code],
    )


class AuthServerConfigValidationResult(BaseModel):
    is_valid: bool
    errors: List[AuthServerConfigError]
    warnings: List[AuthServerConfigWarning]


def validate_server_config(
    config: AuthServerConfig,
) -> AuthServerConfigValidationResult:
    """
    Validates the authorization server configuration against the MCP specification.

    Args:
      config: The configuration object containing the server metadata to validate.

    Returns:
      An object indicating whether the configuration is valid (`{ is_valid: True }`) or
      invalid (`{ is_valid: False }`), along with any errors or warnings encountered during validation.
    """

    errors: List[AuthServerConfigError] = []
    warnings: List[AuthServerConfigWarning] = []
    metadata = config.metadata

    # Check if 'code' is included in any of the supported response types
    has_code_response_type = any(
        "code" in response_type.split(" ")
        for response_type in metadata.response_types_supported
    )
    if not has_code_response_type:
        errors.append(
            _create_error(AuthServerConfigErrorCode.CODE_RESPONSE_TYPE_NOT_SUPPORTED)
        )

    # Check if 'authorization_code' grant type is supported
    if (
        not metadata.grant_types_supported
        or "authorization_code" not in metadata.grant_types_supported
    ):
        errors.append(
            _create_error(
                AuthServerConfigErrorCode.AUTHORIZATION_CODE_GRANT_NOT_SUPPORTED
            )
        )

    # Check PKCE support
    if not metadata.code_challenge_methods_supported:
        errors.append(_create_error(AuthServerConfigErrorCode.PKCE_NOT_SUPPORTED))
    elif "S256" not in metadata.code_challenge_methods_supported:
        errors.append(
            _create_error(
                AuthServerConfigErrorCode.S256_CODE_CHALLENGE_METHOD_NOT_SUPPORTED
            )
        )

    # Check dynamic client registration support
    if not metadata.registration_endpoint:
        warnings.append(
            _create_warning(
                AuthServerConfigWarningCode.DYNAMIC_REGISTRATION_NOT_SUPPORTED
            )
        )

    if len(errors) == 0:
        return AuthServerConfigValidationResult(
            is_valid=True, errors=[], warnings=warnings
        )
    else:
        return AuthServerConfigValidationResult(
            is_valid=False, errors=errors, warnings=warnings
        )
