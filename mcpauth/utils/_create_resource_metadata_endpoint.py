from urllib.parse import urlparse, urlunparse

RESOURCE_METADATA_BASE_PATH = "/.well-known/oauth-protected-resource"


def create_resource_metadata_endpoint(resource: str) -> str:
    """
    Constructs the correct protected resource metadata URL from a resource identifier URI.

    This utility implements the path construction logic from RFC 9728, Section 3.1.
    It correctly handles resource identifiers with and without path components by inserting
    the well-known path segment between the host and the resource's path.

    e.g.
    - 'https://api.example.com' -> '.../.well-known/oauth-protected-resource'
    - 'https://api.example.com/billing' -> '.../.well-known/oauth-protected-resource/billing'
    """
    try:
        parsed_url = urlparse(resource)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid resource identifier URI: {resource}")

        path = (
            RESOURCE_METADATA_BASE_PATH
            if parsed_url.path == "/"
            else f"{RESOURCE_METADATA_BASE_PATH}{parsed_url.path}"
        )

        return urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                path,
                "",  # params
                "",  # query
                "",  # fragment
            )
        )
    except ValueError as e:
        raise TypeError(f"Invalid resource identifier URI: {resource}") from e 
