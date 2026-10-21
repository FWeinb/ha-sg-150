"""Setting up and unloading the integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.helpers import device_registry as dr

from custom_components.sg_150.const import DOMAIN
from tests.conftest import API_URL

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant_custom_component.common import MockConfigEntry
    from pytest_homeassistant_custom_component.test_util.aiohttp import (
        AiohttpClientMocker,
    )

    from custom_components.sg_150.sip.minisip import MiniSIPServer


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


@pytest.mark.xfail(reason="the config flow has no reauth step", strict=True)
async def test_rejected_credentials_on_update_start_reauth(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    gateway_api: AiohttpClientMocker,
    setup_integration: MiniSIPServer,
) -> None:
    """A 401 during a refresh raises ConfigEntryAuthFailed, which starts reauth."""
    gateway_api.clear_requests()
    gateway_api.get(f"{API_URL}/system/devices", status=401)

    await config_entry.runtime_data.coordinator.async_refresh()
    await hass.async_block_till_done()

    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [flow["context"]["source"] for flow in flows] == ["reauth"]


@pytest.mark.xfail(
    reason="machine info auth errors are not ConfigEntryAuthFailed, and the "
    "config flow has no reauth step; setup retries forever instead",
    strict=True,
)
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
