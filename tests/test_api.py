"""Tests for the SG150 HTTP API client."""

import unittest

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from custom_components.sg_150.api import (
    SG150ApiClient,
    SG150ApiClientAuthenticationError,
    SG150ApiClientCommunicationError,
)

TOKEN_RESPONSE = {
    "access_token": "token",
    "token_type": "bearer",
    "refresh_token": "refresh",
    "expires_in": 3600,
    "scope": "read write",
}


@pytest.mark.usefixtures("socket_enabled")
class ApiClientTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the API client against a local HTTP server."""

    async def _client_for(self, app: web.Application) -> SG150ApiClient:
        server = TestServer(app)
        await server.start_server()
        self.addAsyncCleanup(server.close)
        session = aiohttp.ClientSession()
        self.addAsyncCleanup(session.close)
        return SG150ApiClient(
            host_address=server.host,
            port=server.port,
            username="user",
            password="password",  # noqa: S106
            session=session,
        )

    async def test_unauthorized_token_request_raises_authentication_error(
        self,
    ) -> None:
        """A 401 from the token endpoint must surface as an auth error."""

        async def token(_: web.Request) -> web.Response:
            return web.json_response({"error": "invalid_grant"}, status=401)

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        client = await self._client_for(app)

        with pytest.raises(SG150ApiClientAuthenticationError):
            await client.async_get_machine_info()

    async def test_forbidden_request_raises_authentication_error(self) -> None:
        """A 403 from an authenticated endpoint must surface as an auth error."""

        async def token(_: web.Request) -> web.Response:
            return web.json_response(TOKEN_RESPONSE)

        async def machine_info(_: web.Request) -> web.Response:
            return web.json_response({}, status=403)

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_get("/api/op/v1.0/system/machineInfo", machine_info)
        client = await self._client_for(app)

        with pytest.raises(SG150ApiClientAuthenticationError):
            await client.async_get_machine_info()

    async def test_server_error_raises_communication_error(self) -> None:
        """A 5xx response is a communication problem, not an auth problem."""

        async def token(_: web.Request) -> web.Response:
            return web.json_response({}, status=500)

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        client = await self._client_for(app)

        with pytest.raises(SG150ApiClientCommunicationError):
            await client.async_get_machine_info()

    async def test_token_is_requested_on_first_call_and_reused(self) -> None:
        """The client authenticates once and reuses the bearer token."""
        token_requests = 0
        seen_authorization: list[str | None] = []

        async def token(_: web.Request) -> web.Response:
            nonlocal token_requests
            token_requests += 1
            return web.json_response(TOKEN_RESPONSE)

        async def light(request: web.Request) -> web.Response:
            seen_authorization.append(request.headers.get("Authorization"))
            return web.json_response({})

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_post("/api/op/v1.0/in-home/switchLightRequests", light)
        client = await self._client_for(app)

        await client.async_trigger_light_switch()
        await client.async_trigger_light_switch()

        assert token_requests == 1
        assert seen_authorization == ["Bearer token", "Bearer token"]
