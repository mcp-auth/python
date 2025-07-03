from mcpauth.utils._bearer_www_authenticate_header import BearerWWWAuthenticateHeader


class TestBearerWWWAuthenticateHeader:
    def test_should_have_the_correct_header_name(self):
        header = BearerWWWAuthenticateHeader()
        assert header.header_name == "WWW-Authenticate"

    def test_should_generate_an_empty_string_if_no_parameters_are_set(self):
        header = BearerWWWAuthenticateHeader()
        assert header.to_string() == ""

    def test_should_build_the_header_string_correctly_from_chained_calls(self):
        header = BearerWWWAuthenticateHeader()
        header.set_parameter_if_value_exists("realm", "example").set_parameter_if_value_exists(
            "error", "invalid_token"
        ).set_parameter_if_value_exists(
            "error_description", "The access token expired"
        ).set_parameter_if_value_exists(
            "resource_metadata",
            "https://example.com/.well-known/oauth-protected-resource",
        )

        expected = 'Bearer realm="example", error="invalid_token", error_description="The access token expired", resource_metadata="https://example.com/.well-known/oauth-protected-resource"'
        assert header.to_string() == expected

    def test_should_ignore_parameters_that_are_empty_or_none(self):
        header = BearerWWWAuthenticateHeader()
        header.set_parameter_if_value_exists(
            "realm", "example"
        ).set_parameter_if_value_exists("scope", "").set_parameter_if_value_exists(
            "error", "invalid_token"
        ).set_parameter_if_value_exists(
            "error_uri", None
        ).set_parameter_if_value_exists(
            "error_description", ""
        )

        expected = 'Bearer realm="example", error="invalid_token"'
        assert header.to_string() == expected 
