"""Setting up and unloading the integration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMockResponse

from custom_components.sg_150.const import CONF_SIP_PORT, DOMAIN
from custom_components.sg_150.sip.minisip import MiniSIPServer
from tests.conftest import API_URL, HOST, TOKEN
from tests.utils import FIXTURES

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant.common import MockConfigEntry
    from pytest_homeassistant.test_util.aiohttp import (
        AiohttpClientMocker,
    )
    from yarl import URL


async def test_setup_creates_gateway_and_devices(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    setup_integration: MiniSIPServer,
) -> None:
    """The gateway and every device with an entity appear in the registry."""
    assert config_entry.state is ConfigEntryState.LOADED
    assert setup_integration.transport is not None

    registry = dr.async_get(hass)
    devices = dr.async_entries_for_config_entry(registry, config_entry.entry_id)
    identifiers = {next(iter(d.identifiers))[1] for d in devices}
    assert identifiers == {
        config_entry.entry_id,
        "door-front",
        "door-back",
        "pbx-external",
        "pbx-internal-phone",
    }

    gateway = registry.async_get_device_by_identifier(
        (DOMAIN, config_entry.entry_id), config_entry.entry_id
    )
    assert all(d.via_device_id == gateway.id for d in devices if d.id != gateway.id)


async def test_sip_server_trusts_the_configured_gateway(
    setup_integration: MiniSIPServer,
) -> None:
    """The gateway's host is trusted before it registers, other hosts are not."""
    assert setup_integration.is_trusted((HOST, 5060))
    assert not setup_integration.is_trusted(("192.0.2.99", 5060))


async def test_unload_stops_sip_and_keeps_services(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    setup_integration: MiniSIPServer,
) -> None:
    """Unloading stops the SIP server; the services stay and report the error."""
    assert await hass.config_entries.async_unload(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.NOT_LOADED
    assert setup_integration.transport is None
    response = await hass.services.async_call(
        DOMAIN, "start_call", {"to": "*111"}, blocking=True, return_response=True
    )
    assert response == {"error": "No SG-150 gateway is loaded"}


async def test_rejected_credentials_on_update_start_reauth(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    gateway_api: AiohttpClientMocker,
    setup_integration: MiniSIPServer,
) -> None:
    """Credentials rejected during a refresh start reauth."""
    gateway_api.clear_requests()
    gateway_api.get(f"{API_URL}/system/devices", status=401)
    gateway_api.post(f"{API_URL}/oauth/token", status=401)

    await config_entry.runtime_data.coordinator.async_refresh()
    await hass.async_block_till_done()

    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [flow["context"]["source"] for flow in flows] == ["reauth"]


async def test_rejected_credentials_during_setup_start_reauth(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    sip_servers: list[MiniSIPServer],
) -> None:
    """A 401 while setting up fails the setup and asks for new credentials."""
    aioclient_mock.post(f"{API_URL}/oauth/token", status=401)
    config_entry.add_to_hass(hass)

    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [flow["context"]["source"] for flow in flows] == ["reauth"]


async def test_busy_sip_port_retries_setup(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    gateway_api: AiohttpClientMocker,
) -> None:
    """A SIP port that is in use fails the setup before any entity is created."""
    config_entry.add_to_hass(hass)

    with patch.object(
        MiniSIPServer, "start", side_effect=OSError(48, "Address already in use")
    ):
        await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.SETUP_RETRY
    assert not hass.states.async_all()


async def test_failed_platform_unload_keeps_sip_running(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    setup_integration: MiniSIPServer,
) -> None:
    """The SIP server only stops once the platforms unloaded."""
    with patch.object(
        hass.config_entries, "async_unload_platforms", return_value=False
    ):
        assert not await hass.config_entries.async_unload(config_entry.entry_id)

    assert setup_integration.transport is not None


async def test_rejected_cached_token_is_renewed_without_reauth(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    gateway_api: AiohttpClientMocker,
    setup_integration: MiniSIPServer,
) -> None:
    """A gateway that drops its tokens early gets a new token, not a reauth."""
    devices = json.loads((FIXTURES / "system_devices.json").read_text())
    rejected = False

    async def reject_once(
        method: str, url: URL, _: object
    ) -> AiohttpClientMockResponse:
        nonlocal rejected
        if rejected:
            return AiohttpClientMockResponse(method, url, json=devices)
        rejected = True
        return AiohttpClientMockResponse(method, url, status=401)

    gateway_api.clear_requests()
    gateway_api.post(f"{API_URL}/oauth/token", json=TOKEN)
    gateway_api.get(f"{API_URL}/system/devices", side_effect=reject_once)

    coordinator = config_entry.runtime_data.coordinator
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert coordinator.last_update_success
    assert [str(url).rsplit("/", 1)[-1] for _, url, _, _ in gateway_api.mock_calls] == [
        "devices",
        "token",
        "devices",
    ]
    assert not hass.config_entries.flow.async_progress_by_handler(DOMAIN)


async def test_invalid_stored_port_fails_setup_clearly(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    gateway_api: AiohttpClientMocker,
    sip_servers: list[MiniSIPServer],
) -> None:
    """A non-numeric port stored by an older version ends in SETUP_ERROR."""
    config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        config_entry, options={**config_entry.options, CONF_SIP_PORT: "sip"}
    )

    await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    assert config_entry.state is ConfigEntryState.SETUP_ERROR
    assert "Invalid SIP or RTP port" in config_entry.reason
    assert not sip_servers
