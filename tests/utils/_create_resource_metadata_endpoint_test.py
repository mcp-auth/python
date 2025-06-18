import pytest

from mcpauth.utils._create_resource_metadata_endpoint import (
    create_resource_metadata_endpoint,
)


def test_should_throw_an_error_if_the_resource_is_not_a_valid_url():
    with pytest.raises(TypeError, match="Invalid resource identifier URI: not a url"):
        create_resource_metadata_endpoint("not a url")


def test_should_return_the_metadata_endpoint_for_a_resource_with_no_path():
    resource = "https://example.com"
    metadata_endpoint = create_resource_metadata_endpoint(resource)
    assert (
        metadata_endpoint == "https://example.com/.well-known/oauth-protected-resource"
    )


def test_should_return_the_metadata_endpoint_for_a_resource_with_root_path():
    resource = "https://example.com/"
    metadata_endpoint = create_resource_metadata_endpoint(resource)
    assert (
        metadata_endpoint == "https://example.com/.well-known/oauth-protected-resource"
    )


def test_should_return_the_metadata_endpoint_for_a_resource_with_a_sub_path():
    resource = "https://example.com/api/v1"
    metadata_endpoint = create_resource_metadata_endpoint(resource)
    assert (
        metadata_endpoint
        == "https://example.com/.well-known/oauth-protected-resource/api/v1"
    )


def test_should_return_the_metadata_endpoint_for_a_resource_with_a_sub_path_and_trailing_slash():
    resource = "https://example.com/api/v1/"
    metadata_endpoint = create_resource_metadata_endpoint(resource)
    assert (
        metadata_endpoint
        == "https://example.com/.well-known/oauth-protected-resource/api/v1/"
    )


def test_should_preserve_the_origin_of_the_resource():
    resource = "http://localhost:3000/foo"
    metadata_endpoint = create_resource_metadata_endpoint(resource)
    assert (
        metadata_endpoint
        == "http://localhost:3000/.well-known/oauth-protected-resource/foo"
    )


def test_should_ignore_query_parameters_and_hash_from_the_resource():
    resource = "https://example.com/api/v1?foo=bar#baz"
    metadata_endpoint = create_resource_metadata_endpoint(resource)
    assert (
        metadata_endpoint
        == "https://example.com/.well-known/oauth-protected-resource/api/v1"
    ) 
