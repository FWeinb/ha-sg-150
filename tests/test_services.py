"""Tests for the integration services."""

import unittest
from unittest.mock import MagicMock

from homeassistant.core import SupportsResponse

from custom_components.sg_150.const import DOMAIN
from custom_components.sg_150.line import GatewayLine
from custom_components.sg_150.services import (
    async_setup_services,
    handle_get_active_calls,
    handle_start_call,
    handle_stop_call,
)
from custom_components.sg_150.sip.minisip import MiniSIPServer
from tests.test_line import GATEWAY, HA_NUMBER, invite
from tests.utils import FakeTransport, load_devices


def make_line() -> tuple[GatewayLine, MiniSIPServer]:
    """Create a line on a server with a fake transport."""
    server = MiniSIPServer({"gateway": "pw"}, host="127.0.0.1", call_host="127.0.0.1")
    server.transport = FakeTransport()
    devices = load_devices()
    line = GatewayLine(
        server,
        user="gateway",
        number=HA_NUMBER,
        auto_answer=True,
        devices=devices.values,
    )
    return line, server


def make_hass(*lines: GatewayLine) -> MagicMock:
    """Create a hass stub with one loaded config entry per line."""
    entries = []
    for index, line in enumerate(lines):
        entry = MagicMock(entry_id=f"entry-{index}")
        entry.runtime_data.line = line
        entries.append(entry)
    hass = MagicMock()
    hass.config_entries.async_loaded_entries.return_value = entries
    return hass


def service_call(*, return_response: bool = True, **data: object) -> MagicMock:
    """Create a ServiceCall stub."""
    return MagicMock(data=data, return_response=return_response)


class ServiceRegistrationTests(unittest.TestCase):
    """Services are registered once, independent of config entries."""

    def test_registers_each_service_once_with_its_response_mode(self) -> None:
        """All five services are registered with their response contract."""
        hass = MagicMock()

        async_setup_services(hass)

        registered = {
            args[1]: kwargs["supports_response"]
            for args, kwargs in hass.services.async_register.call_args_list
        }
        assert registered == {
            "start_call": SupportsResponse.ONLY,
            "stop_call": SupportsResponse.OPTIONAL,
            "send_sip_info_dtmf": SupportsResponse.OPTIONAL,
            "get_active_calls": SupportsResponse.ONLY,
            "play_audio": SupportsResponse.OPTIONAL,
        }
        assert all(
            args[0] == DOMAIN for args, _ in hass.services.async_register.call_args_list
        )


class ServiceTargetTests(unittest.IsolatedAsyncioTestCase):
    """Each call resolves its gateway from the loaded config entries."""

    async def test_single_gateway_is_used_without_config_entry_id(self) -> None:
        """With one gateway the call needs no target."""
        line, server = make_line()
        await server.handle_datagram(invite("call-1", "*111", HA_NUMBER), GATEWAY)

        response = await handle_get_active_calls(make_hass(line), service_call())

        assert response == {
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

    async def test_config_entry_id_selects_the_gateway(self) -> None:
        """With several gateways, config_entry_id picks one."""
        first, _ = make_line()
        second, second_server = make_line()
        await second_server.handle_datagram(
            invite("call-2", "*111", HA_NUMBER), GATEWAY
        )
        hass = make_hass(first, second)

        response = await handle_get_active_calls(
            hass, service_call(config_entry_id="entry-1")
        )

        assert response["active_calls"] == ["call-2"]

    async def test_errors_are_returned_in_the_response(self) -> None:
        """Targeting problems are reported as {"error": ...}, not raised."""
        line, _ = make_line()

        ambiguous = await handle_start_call(
            make_hass(line, line), service_call(to="*111")
        )
        unknown = await handle_start_call(
            make_hass(line), service_call(to="*111", config_entry_id="nope")
        )
        none_loaded = await handle_start_call(make_hass(), service_call(to="*111"))
        not_registered = await handle_start_call(
            make_hass(line), service_call(to="*111")
        )

        assert ambiguous == {
            "error": "Several SG-150 gateways are loaded, specify config_entry_id"
        }
        assert unknown == {
            "error": "No loaded SG-150 gateway with config entry id: nope"
        }
        assert none_loaded == {"error": "No SG-150 gateway is loaded"}
        assert not_registered == {"error": "Not Connected"}

    async def test_optional_responses_are_only_returned_when_requested(self) -> None:
        """OPTIONAL services return nothing unless a response was asked for."""
        line, server = make_line()
        await server.handle_datagram(invite("call-3", "*111", HA_NUMBER), GATEWAY)
        hass = make_hass(line)

        unknown = await handle_stop_call(hass, service_call(call_id="missing"))
        silent = await handle_stop_call(
            hass, service_call(call_id="call-3", return_response=False)
        )

        assert unknown == {
            "error": "There is currently no active call with call id: missing"
        }
        assert silent is None
        assert not line.calls
