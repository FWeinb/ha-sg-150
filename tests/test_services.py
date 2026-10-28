"""The integration's services, called through Home Assistant."""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.sg_150.const import API_PORT, CONF_HOST_ADDRESS, DOMAIN
from tests.conftest import MACHINE_INFO, TOKEN
from tests.sip_messages import (
    GATEWAY,
    HA_HOST,
    HA_NUMBER,
    ack,
    invite,
    register,
    sip,
)
from tests.utils import FIXTURES

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant, ServiceResponse
    from pytest_homeassistant.test_util.aiohttp import (
        AiohttpClientMocker,
    )

    from custom_components.sg_150.sip.minisip import MiniSIPServer

SERVICES = [
    "start_call",
    "stop_call",
    "send_sip_info_dtmf",
    "get_active_calls",
    "play_audio",
]


async def call(
    hass: HomeAssistant, service: str, *, return_response: bool = True, **data: object
) -> ServiceResponse:
    """Call one of the integration's services."""
    return await hass.services.async_call(
        DOMAIN, service, data, blocking=True, return_response=return_response
    )


async def establish_incoming_call(server: MiniSIPServer, call_id: str) -> None:
    """Let the front door call Home Assistant and complete the handshake."""
    await server.handle_datagram(invite(call_id, "*111", HA_NUMBER), GATEWAY)
    await server.handle_datagram(ack(call_id), GATEWAY)


@pytest.fixture
async def second_gateway(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    setup_integration: MiniSIPServer,
    sip_servers: list[MiniSIPServer],
) -> tuple[MockConfigEntry, MiniSIPServer]:
    """Set up a second gateway next to the first one."""
    host = "192.0.2.11"
    api = f"http://{host}:{API_PORT}/api/op/v1.0"
    devices = json.loads((FIXTURES / "system_devices.json").read_text())
    aioclient_mock.post(f"{api}/oauth/token", json=TOKEN)
    aioclient_mock.get(
        f"{api}/system/machineInfo",
        json={**MACHINE_INFO, "macAddress": "00:11:22:33:44:66"},
    )
    aioclient_mock.get(f"{api}/system/devices", json=devices)

    entry = MockConfigEntry(
        domain=DOMAIN,
        title=host,
        unique_id=host,
        data={**config_entry.data, CONF_HOST_ADDRESS: host},
        options=dict(config_entry.options),
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry, sip_servers[1]


@pytest.mark.usefixtures("setup_integration")
async def test_services_are_registered(hass: HomeAssistant) -> None:
    """Every service is available once the integration is set up."""
    assert all(hass.services.has_service(DOMAIN, name) for name in SERVICES)


async def test_get_active_calls_lists_calls_with_devices(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """Active calls carry their direction and the matched devices."""
    await establish_incoming_call(setup_integration, "call-1")

    assert await call(hass, "get_active_calls") == {
        "active_calls": ["call-1"],
        "calls": [
            {
                "call_id": "call-1",
                "direction": "incoming",
                "caller": {"id": "door-front", "name": "Front Door"},
                "callee": {"id": "pbx-external", "name": "Home Assistant"},
            }
        ],
    }


async def test_start_call_returns_the_call_id(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """start_call dials through the registered gateway and returns the call id."""
    server = setup_integration
    assert await call(hass, "start_call", to="*111") == {"error": "Not Connected"}

    await register(server)
    server.transport.sent.clear()
    pending = hass.async_create_task(call(hass, "start_call", to="*111"))
    while not server.transport.sent:  # noqa: ASYNC110
        await asyncio.sleep(0)
    request = server.transport.sent[0][0].decode()
    call_id = re.search(r"Call-ID: (.+)\r\n", request).group(1)
    await server.handle_datagram(
        sip(
            "SIP/2.0 200 OK",
            {
                "Via": f"SIP/2.0/UDP {HA_HOST}:5060;branch=z3",
                "From": f"<sip:{HA_NUMBER}@{HA_HOST}>",
                "To": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
                "Call-ID": call_id,
                "CSeq": "1 INVITE",
                "Contact": f"<sip:*111@{GATEWAY[0]}>",
            },
        ),
        GATEWAY,
    )

    assert await pending == {"call_id": call_id, "error": None}


async def test_stop_call_responds_only_when_asked(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """OPTIONAL services report errors as data and stay silent otherwise."""
    await establish_incoming_call(setup_integration, "call-2")

    assert await call(hass, "stop_call", call_id="missing") == {
        "error": "There is currently no active call with call id: missing"
    }
    assert await call(hass, "stop_call", call_id="call-2") == {
        "success": True,
        "error": None,
    }
    await establish_incoming_call(setup_integration, "call-3")
    assert (
        await call(hass, "stop_call", return_response=False, call_id="call-3") is None
    )
    assert (await call(hass, "get_active_calls"))["active_calls"] == []


async def test_config_entry_id_selects_the_gateway(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    second_gateway: tuple[MockConfigEntry, MiniSIPServer],
) -> None:
    """With two gateways a call must name one with config_entry_id."""
    entry, server = second_gateway
    await establish_incoming_call(server, "call-4")

    assert await call(hass, "get_active_calls", config_entry_id=entry.entry_id) == {
        "active_calls": ["call-4"],
        "calls": [
            {
                "call_id": "call-4",
                "direction": "incoming",
                "caller": {"id": "door-front", "name": "Front Door"},
                "callee": {"id": "pbx-external", "name": "Home Assistant"},
            }
        ],
    }
    first = await call(hass, "get_active_calls", config_entry_id=config_entry.entry_id)
    assert first["active_calls"] == []
    assert await call(hass, "start_call", to="*111") == {
        "error": "Several SG-150 gateways are loaded, specify config_entry_id"
    }
