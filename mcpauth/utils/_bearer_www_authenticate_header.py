from typing import Dict, Optional


class BearerWWWAuthenticateHeader:
    """
    A simple implementation for generating WWW-Authenticate response headers
    specifically for Bearer authentication scheme, based on RFC 6750.
    """

    def __init__(self):
        self._params: Dict[str, str] = {}

    def set_parameter_if_value_exists(self, param: str, value: Optional[str]):
        if value:
            self._params[param] = value
        return self

    def to_string(self) -> str:
        if not self._params:
            return ""

        params_str = ", ".join([f'{key}="{value}"' for key, value in self._params.items()])
        return f"Bearer {params_str}"

    @property
    def header_name(self) -> str:
        return "WWW-Authenticate" 
