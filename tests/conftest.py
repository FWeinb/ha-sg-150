"""Fixtures for tests that run the integration inside Home Assistant."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.sg_150.const import (
    API_PORT,
    CONF_HOST_ADDRESS,
    CONF_SIP_AUTO_ANSWER,
    CONF_SIP_CALLER_IP,
    CONF_SIP_NUMBER,
    CONF_SIP_PASSWORD,
    CONF_SIP_PORT,
    CONF_SIP_USER,
    DOMAIN,
)
from custom_components.sg_150.sip.minisip import MiniSIPServer
from tests.utils import FIXTURES, FakeTransport, fake_rtp_endpoint

if TYPE_CHECKING:
    from collections.abc import Generator

    from homeassistant.core import HomeAssistant
    from pytest_homeassistant.test_util.aiohttp import (
        AiohttpClientMocker,
    )

HOST = "192.0.2.10"
API_URL = f"http://{HOST}:{API_PORT}/api/op/v1.0"
MAC = "00:11:22:33:44:55"
SIP_USER = "gateway"
SIP_PASSWORD = "secret"  # noqa: S105
HA_NUMBER = "*2620"

MACHINE_INFO = {
    "machineModel": "SG 150-0",
    "machineName": "Smart Gateway",
    "machineRevision": "1",
    "productionBatch": 1,
    "macAddress": MAC,
}
TOKEN = {
    "access_token": "token",
    "token_type": "bearer",
    "refresh_token": "refresh",
    "expires_in": 3600,
}


@pytest.fixture
def config_entry() -> MockConfigEntry:
    """Return a config entry for one gateway."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=HOST,
        unique_id=HOST,
        data={
            CONF_HOST_ADDRESS: HOST,
            "username": "admin",
            "password": "hashed",
        },
        options={
            CONF_SIP_CALLER_IP: "127.0.0.1",
            CONF_SIP_USER: SIP_USER,
            CONF_SIP_PASSWORD: SIP_PASSWORD,
            CONF_SIP_NUMBER: HA_NUMBER,
            CONF_SIP_PORT: "5060",
            CONF_SIP_AUTO_ANSWER: True,
        },
    )


@pytest.fixture
def gateway_api(aioclient_mock: AiohttpClientMocker) -> AiohttpClientMocker:
    """Fake the gateway's HTTP API with the system/devices fixture."""
    devices = json.loads((FIXTURES / "system_devices.json").read_text())
    aioclient_mock.post(f"{API_URL}/oauth/token", json=TOKEN)
    aioclient_mock.get(f"{API_URL}/system/machineInfo", json=MACHINE_INFO)
    aioclient_mock.get(f"{API_URL}/system/devices", json=devices)
    aioclient_mock.post(f"{API_URL}/in-home/openDoorRequests", json={})
    aioclient_mock.post(f"{API_URL}/in-home/switchLightRequests", json={})
    return aioclient_mock


@pytest.fixture
def sip_servers() -> Generator[list[MiniSIPServer]]:
    """Start SIP servers on fake transports instead of UDP sockets."""
    started: list[MiniSIPServer] = []

    async def start(self: MiniSIPServer) -> None:
        self.transport = FakeTransport()
        self._rtp_endpoint = fake_rtp_endpoint
        started.append(self)

    with patch.object(MiniSIPServer, "start", start):
        yield started


@pytest.fixture
async def setup_integration(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    gateway_api: AiohttpClientMocker,
    sip_servers: list[MiniSIPServer],
) -> MiniSIPServer:
    """Set up the integration and return its SIP server."""
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()
    return sip_servers[0]
