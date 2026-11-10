"""The integration's services, called through Home Assistant."""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import voluptuous as vol
from homeassistant.components.media_source import PlayMedia, Unresolvable
from homeassistant.exceptions import HomeAssistantError
from pytest_homeassistant.common import MockConfigEntry

from custom_components.sg_150 import services
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

SECOND_GATEWAY = ("192.0.2.11", 5060)


async def call(
    hass: HomeAssistant, service: str, *, return_response: bool = True, **data: object
) -> ServiceResponse:
    """Call one of the integration's services."""
    return await hass.services.async_call(
        DOMAIN, service, data, blocking=True, return_response=return_response
    )


async def establish_incoming_call(
    server: MiniSIPServer, call_id: str, gateway: tuple[str, int] = GATEWAY
) -> None:
    """Let the front door call Home Assistant and complete the handshake."""
    await server.handle_datagram(invite(call_id, "*111", HA_NUMBER), gateway)
    await server.handle_datagram(ack(call_id), gateway)


@pytest.fixture
async def second_gateway(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    setup_integration: MiniSIPServer,
    sip_servers: list[MiniSIPServer],
) -> tuple[MockConfigEntry, MiniSIPServer]:
    """Set up a second gateway next to the first one."""
    host = SECOND_GATEWAY[0]
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
    await establish_incoming_call(server, "call-4", SECOND_GATEWAY)

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


@pytest.mark.usefixtures("setup_integration")
@pytest.mark.parametrize(
    ("service", "data"),
    [
        ("start_call", {}),
        ("start_call", {"to": "*111\r\nVia: x"}),
        ("start_call", {"to": "sip:evil@host"}),
        ("stop_call", {}),
        ("send_sip_info_dtmf", {"call_id": "c", "signal": "1;x"}),
        ("send_sip_info_dtmf", {"call_id": "c", "signal": "1", "duration": "0"}),
        ("play_audio", {"call_id": "c"}),
    ],
)
async def test_invalid_service_data_is_rejected(
    hass: HomeAssistant, service: str, data: dict[str, str]
) -> None:
    """The schemas keep anything but dial characters out of SIP messages."""
    with pytest.raises(vol.Invalid):
        await call(hass, service, return_response=service == "start_call", **data)


async def test_dtmf_signal_is_sent_upper_case(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """A lower-case DTMF letter is accepted and sent as the upper-case signal."""
    await establish_incoming_call(setup_integration, "call-5")

    await call(
        hass, "send_sip_info_dtmf", return_response=False, call_id="call-5", signal="a"
    )

    info = next(
        data.decode()
        for data, _ in setup_integration.transport.sent
        if data.startswith(b"INFO ")
    )
    assert info.endswith("Signal=A\r\nDuration=100")


@pytest.mark.usefixtures("setup_integration")
async def test_errors_raise_when_no_response_is_asked_for(
    hass: HomeAssistant,
) -> None:
    """Without return_response a failure shows up as HomeAssistantError."""
    with pytest.raises(HomeAssistantError, match="no active call"):
        await call(hass, "stop_call", return_response=False, call_id="missing")


async def test_unresolvable_media_is_reported(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """A media source that cannot be resolved is an error, not a crash."""
    await establish_incoming_call(setup_integration, "call-6")

    with patch.object(
        services.media_source,
        "async_resolve_media",
        side_effect=Unresolvable("Unknown media source"),
    ):
        response = await call(
            hass, "play_audio", call_id="call-6", media_source_id="media-source://x"
        )

    assert response == {"error": "Unknown media source"}


@pytest.mark.parametrize(
    ("mock", "error"),
    [
        ({"content": b"\0" * (services.MAX_AUDIO_BYTES + 1)}, "larger than"),
        ({"exc": TimeoutError()}, "Could not download"),
        ({"status": 404}, "status 404"),
    ],
)
async def test_media_downloads_are_limited(
    hass: HomeAssistant,
    setup_integration: MiniSIPServer,
    aioclient_mock: AiohttpClientMocker,
    mock: dict[str, object],
    error: str,
) -> None:
    """Large, slow or failing downloads end in an error response."""
    await establish_incoming_call(setup_integration, "call-7")
    aioclient_mock.get("http://media.test/clip.wav", **mock)

    with patch.object(
        services.media_source,
        "async_resolve_media",
        return_value=PlayMedia("http://media.test/clip.wav", "audio/wav"),
    ):
        response = await call(
            hass, "play_audio", call_id="call-7", media_source_id="media-source://x"
        )

    assert error in response["error"]
