from abc import ABC, abstractmethod

from starlette.routing import Router

from .token_verifier import TokenVerifier


class MCPAuthHandler(ABC):
    """
    Defines the contract for a handler that manages the logic for a specific MCPAuth configuration.
    This allows for clean separation of logic between legacy and modern configurations.
    """

    @abstractmethod
    def create_metadata_route(self) -> Router:
        """
        Returns a router for serving either the legacy OAuth 2.0 Authorization Server Metadata or
        the OAuth 2.0 Protected Resource Metadata, depending on the configuration.
        """
        ...  # pragma: no cover

    @abstractmethod
    def get_token_verifier(self, resource: str) -> TokenVerifier:
        """
        Resolves the appropriate TokenVerifier based on the provided resource.
        :param resource: The resource identifier for verifier lookup.
        """
        ...  # pragma: no cover 
