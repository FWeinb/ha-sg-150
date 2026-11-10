"""Tests for the SG150 HTTP API client."""

import asyncio
import base64
import json
import unittest

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from custom_components.sg_150.api import (
    SG150ApiClient,
    SG150ApiClientAuthenticationError,
    SG150ApiClientCommunicationError,
    SG150ApiClientError,
)
from tests.utils import FIXTURES

TOKEN_RESPONSE = {
    "access_token": "token",
    "token_type": "bearer",
    "refresh_token": "refresh",
    "expires_in": 3600,
    "scope": "read write",
}


async def client_for(
    test: unittest.IsolatedAsyncioTestCase, app: web.Application
) -> SG150ApiClient:
    """Start `app` on a local server and return a client pointed at it."""
    server = TestServer(app)
    await server.start_server()
    test.addAsyncCleanup(server.close)
    session = aiohttp.ClientSession()
    test.addAsyncCleanup(session.close)
    return SG150ApiClient(
        host_address=server.host,
        port=server.port,
        username="user",
        password="password",  # noqa: S106
        session=session,
    )


@pytest.mark.usefixtures("socket_enabled")
class ApiClientTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the API client against a local HTTP server."""

    async def _client_for(self, app: web.Application) -> SG150ApiClient:
        return await client_for(self, app)

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

    async def test_rejected_cached_token_is_renewed_once(self) -> None:
        """A 401 on a cached token fetches a new token and repeats the request."""
        token_requests = 0
        light_statuses = [200, 401, 200]

        async def token(_: web.Request) -> web.Response:
            nonlocal token_requests
            token_requests += 1
            return web.json_response(
                TOKEN_RESPONSE | {"access_token": f"token-{token_requests}"}
            )

        async def light(_: web.Request) -> web.Response:
            return web.json_response({}, status=light_statuses.pop(0))

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_post("/api/op/v1.0/in-home/switchLightRequests", light)
        client = await self._client_for(app)

        await client.async_trigger_light_switch()
        await client.async_trigger_light_switch()

        assert token_requests == 2
        assert not light_statuses

    async def test_rejected_renewed_token_raises_authentication_error(
        self,
    ) -> None:
        """A request rejected with a cached and a fresh token is an auth error."""
        token_requests = 0
        light_statuses = [200, 401, 401]

        async def token(_: web.Request) -> web.Response:
            nonlocal token_requests
            token_requests += 1
            return web.json_response(TOKEN_RESPONSE)

        async def light(_: web.Request) -> web.Response:
            return web.json_response({}, status=light_statuses.pop(0))

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_post("/api/op/v1.0/in-home/switchLightRequests", light)
        client = await self._client_for(app)

        await client.async_trigger_light_switch()
        with pytest.raises(SG150ApiClientAuthenticationError):
            await client.async_trigger_light_switch()

        assert token_requests == 2
        assert not light_statuses

    async def test_parallel_requests_share_one_token_request(self) -> None:
        """Concurrent requests without a token wait for one token request."""
        token_requests = 0

        async def token(_: web.Request) -> web.Response:
            nonlocal token_requests
            token_requests += 1
            await asyncio.sleep(0.01)
            return web.json_response(TOKEN_RESPONSE)

        async def light(_: web.Request) -> web.Response:
            return web.json_response({})

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_post("/api/op/v1.0/in-home/switchLightRequests", light)
        client = await self._client_for(app)

        await asyncio.gather(*(client.async_trigger_light_switch() for _ in range(3)))

        assert token_requests == 1

    async def test_unexpected_responses_raise_client_error(self) -> None:
        """Replies that do not fit the models raise SG150ApiClientError."""

        async def token(_: web.Request) -> web.Response:
            return web.json_response({"token_type": "bearer"})

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        client = await self._client_for(app)

        with pytest.raises(SG150ApiClientError, match="token response"):
            await client.authenticate()


@pytest.mark.usefixtures("socket_enabled")
class DeviceListTests(unittest.IsolatedAsyncioTestCase):
    """Validating the gateway's device list."""

    async def _client_for(self, devices: object) -> SG150ApiClient:
        async def token(_: web.Request) -> web.Response:
            return web.json_response(TOKEN_RESPONSE)

        async def system_devices(_: web.Request) -> web.Response:
            return web.json_response(devices)

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_get("/api/op/v1.0/system/devices", system_devices)
        return await client_for(self, app)

    async def test_device_with_unexpected_data_is_skipped(self) -> None:
        """A device whose known capability changed does not hide the others."""
        payload = json.loads((FIXTURES / "system_devices.json").read_text())
        broken = payload["devices"][0]
        for capability in broken["capabilities"]:
            if capability["type"] == "PHONE_ENDPOINT":
                capability["properties"] = {"isDoor": "maybe"}
        client = await self._client_for(payload)

        with self.assertLogs("custom_components.sg_150", "WARNING") as logs:
            devices = (await client.async_get_in_home_callable()).devices
            await client.async_get_in_home_callable()

        ids = [device.id for device in devices]
        assert broken["id"] not in ids
        assert len(ids) == len(payload["devices"]) - 1
        assert len(logs.records) == 1
        assert broken["id"] in logs.output[0]

    async def test_unexpected_device_list_raises_client_error(self) -> None:
        """A reply without a device list raises SG150ApiClientError."""
        client = await self._client_for(["not", "a", "device", "list"])

        with pytest.raises(SG150ApiClientError, match="device list"):
            await client.async_get_in_home_callable()


@pytest.mark.usefixtures("socket_enabled")
class StoredImageTests(unittest.IsolatedAsyncioTestCase):
    """Decoding the image store's base64 image replies."""

    async def _client_for(self, content: str) -> SG150ApiClient:
        async def token(_: web.Request) -> web.Response:
            return web.json_response(TOKEN_RESPONSE)

        async def image(request: web.Request) -> web.Response:
            return web.json_response(
                {
                    "id": 110,
                    "uid": request.match_info["uid"],
                    "cameraName": "Haustür",
                    "timestamp": "2026-10-17T17:14:23+00:00",
                    "callId": "bbc28f1e-a4ac-4371-9398-119a24652994",
                    "filename": "110_2026-10-17T17:14:23+00:00.jpg",
                    "permissions": [],
                    "content": content,
                }
            )

        app = web.Application()
        app.router.add_post("/api/op/v1.0/oauth/token", token)
        app.router.add_get("/api/op/v1.0/video/imageStore/images/{uid}", image)
        return await client_for(self, app)

    async def test_content_is_decoded(self) -> None:
        """The base64 content is returned as bytes with the file's type."""
        client = await self._client_for(base64.b64encode(b"\xff\xd8jpeg").decode())

        assert await client.async_get_stored_image("uid-1") == (
            b"\xff\xd8jpeg",
            "image/jpeg",
        )

    async def test_empty_or_invalid_content_is_an_error(self) -> None:
        """Images without decodable content raise SG150ApiClientError."""
        for content in ("", "not base64!"):
            client = await self._client_for(content)
            with pytest.raises(SG150ApiClientError):
                await client.async_get_stored_image("uid-1")
