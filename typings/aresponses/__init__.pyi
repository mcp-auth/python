# Created by ChatGPT, edited for precision

from typing import Any, Union
from aiohttp.web_response import Response

class ResponsesMockServer:
    def add(
        self,
        host: str,
        path: str,
        method: str,
        response: Union[Response, Any],
    ) -> None: ...
    async def start(self) -> None: ...
    async def close(self) -> None: ...
    def __aenter__(self) -> "ResponsesMockServer": ...
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...
