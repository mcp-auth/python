from contextvars import ContextVar
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import logging
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.datastructures import Headers

from ..exceptions import (
    MCPAuthBearerAuthException,
    MCPAuthTokenVerificationException,
    MCPAuthAuthServerException,
    MCPAuthConfigException,
    BearerAuthExceptionCode,
    MCPAuthBearerAuthExceptionDetails,
)
from ..types import AuthInfo, VerifyAccessTokenFunction, Record


class BearerAuthConfig(BaseModel):
    """
    Configuration for the Bearer auth handler.
    """

    issuer: str
    """
    The expected issuer of the access token. This should be a valid URL.
    """

    audience: Optional[str] = None
    """
    The expected audience of the access token. If not provided, no audience check is performed.
    """

    required_scopes: Optional[List[str]] = None
    """
    An array of required scopes that the access token must have. If not provided, no scope check is
    performed.
    """

    show_error_details: bool = False
    """
    Whether to show detailed error information in the response. Defaults to False.
    If True, detailed error information will be included in the response body for debugging
    purposes.
    """


def get_bearer_token_from_headers(headers: Headers) -> str:
    """
    Extract the Bearer token from the request headers.

    Args:
      headers: The HTTP request headers.

    Returns:
      The Bearer token.

    Raises:
      MCPAuthBearerAuthException: If the Authorization header is missing or invalid.
    """

    auth_header = headers.get("authorization") or headers.get("Authorization")

    if not auth_header:
        raise MCPAuthBearerAuthException(BearerAuthExceptionCode.MISSING_AUTH_HEADER)

    parts = auth_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise MCPAuthBearerAuthException(
            BearerAuthExceptionCode.INVALID_AUTH_HEADER_FORMAT
        )

    token = parts[1]
    if not token:
        raise MCPAuthBearerAuthException(BearerAuthExceptionCode.MISSING_BEARER_TOKEN)

    return token


def _handle_error(
    error: Exception, show_error_details: bool = False
) -> tuple[int, Dict[str, Any]]:
    """
    Handle errors from the Bearer auth process.

    Args:
      error: The exception that was caught.
      show_error_details: Whether to include detailed error information in the response.

    Returns:
      A tuple of (status_code, response_body).
    """
    if isinstance(error, MCPAuthTokenVerificationException):
        return 401, error.to_json(show_error_details)

    if isinstance(error, MCPAuthBearerAuthException):
        if error.code == BearerAuthExceptionCode.MISSING_REQUIRED_SCOPES:
            return 403, error.to_json(show_error_details)
        return 401, error.to_json(show_error_details)

    if isinstance(error, (MCPAuthAuthServerException, MCPAuthConfigException)):
        response: Record = {
            "error": "server_error",
            "error_description": "An error occurred with the authorization server.",
        }
        if show_error_details:
            response["cause"] = error.to_json()
        return 500, response

    # Re-raise other errors
    raise error


def create_bearer_auth(
    verify_access_token: VerifyAccessTokenFunction,
    config: BearerAuthConfig,
    context_var: ContextVar[Optional[AuthInfo]],
) -> type[BaseHTTPMiddleware]:
    """
    Creates a middleware function for handling Bearer auth.

    This middleware extracts the Bearer token from the `Authorization` header, verifies it using the
    provided `verify_access_token` function, and checks the issuer, audience, and required scopes.

    :param verify_access_token: A function that takes a Bearer token and returns an `AuthInfo` object.
    :param config: Configuration for the Bearer auth handler.
    :param context_var: Context variable to store the `AuthInfo` object for the current request.
    This allows access to the authenticated user's information in later middleware or route handlers.

    :return: A middleware class that handles Bearer auth.
    """

    if not callable(verify_access_token):
        raise TypeError(
            "`verify_access_token` must be a function that takes a token and returns an `AuthInfo` object."
        )

    try:
        result = urlparse(config.issuer)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL")
    except:
        raise TypeError("`issuer` must be a valid URL.")

    class BearerAuthMiddleware(BaseHTTPMiddleware):
        """
        Middleware class that handles Bearer auth.

        This class is used to wrap the request handling process and apply Bearer auth checks.
        """

        async def dispatch(
            self, request: Request, call_next: RequestResponseEndpoint
        ) -> Response:
            """
            Dispatch method that processes the request and applies Bearer auth checks.

            Args:
              request: The HTTP request.
              call_next: The next middleware or route handler to call.

            Returns:
              The HTTP response after processing the request.
            """
            try:
                token = get_bearer_token_from_headers(request.headers)
                auth_info = verify_access_token(token)

                if auth_info.issuer != config.issuer:
                    details = MCPAuthBearerAuthExceptionDetails(
                        expected=config.issuer, actual=auth_info.issuer
                    )
                    raise MCPAuthBearerAuthException(
                        BearerAuthExceptionCode.INVALID_ISSUER, cause=details
                    )

                if config.audience:
                    audience_matches = (
                        config.audience == auth_info.audience
                        if isinstance(auth_info.audience, str)
                        else (
                            isinstance(auth_info.audience, list)
                            and config.audience in auth_info.audience
                        )
                    )
                    if not audience_matches:
                        details = MCPAuthBearerAuthExceptionDetails(
                            expected=config.audience, actual=auth_info.audience
                        )
                        raise MCPAuthBearerAuthException(
                            BearerAuthExceptionCode.INVALID_AUDIENCE, cause=details
                        )

                if config.required_scopes:
                    missing_scopes = [
                        scope
                        for scope in config.required_scopes
                        if scope not in auth_info.scopes
                    ]
                    if missing_scopes:
                        details = MCPAuthBearerAuthExceptionDetails(
                            missing_scopes=missing_scopes
                        )
                        raise MCPAuthBearerAuthException(
                            BearerAuthExceptionCode.MISSING_REQUIRED_SCOPES,
                            cause=details,
                        )

                if context_var.get() is not None:
                    logging.warning(
                        "Overwriting existing auth info in context variable."
                    )

                context_var.set(auth_info)

                # Call the next middleware or route handler
                response = await call_next(request)
                return response

            except Exception as error:
                logging.error(f"Error during Bearer auth: {error}")
                status_code, response_body = _handle_error(
                    error, config.show_error_details
                )
                return JSONResponse(status_code=status_code, content=response_body)

    return BearerAuthMiddleware
