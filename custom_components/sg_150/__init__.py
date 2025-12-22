"""
Custom integration for the Siedle Gateway 150 with Home Assistant.

For more details about this integration, please refer to
https://github.com/fweinb/ha-sg-150
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.loader import async_get_loaded_integration

from .api import SG150ApiClient
from .const import (
    API_PORT,
    CONF_HOST_ADDRESS,
    CONF_SIP_CALLER_IP,
    CONF_SIP_PASSWORD,
    CONF_SIP_PORT,
    CONF_SIP_USER,
)
from .coordinator import SG150Coordinator
from .data import SG150RuntimeData
from .services import setup_services
from .sip.minisip import MiniSIPServer

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import SG150ConfigEntry

PLATFORMS: list[Platform] = [
    Platform.EVENT,
    Platform.CAMERA,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SG150ConfigEntry,
) -> bool:
    """Set up this integration using UI."""
    coordinator = SG150Coordinator(hass=hass)

    client = SG150ApiClient(
        host_address=entry.data.get(CONF_HOST_ADDRESS),
        port=API_PORT,
        username=entry.data.get(CONF_USERNAME),
        password=entry.data.get(CONF_PASSWORD),
        session=async_get_clientsession(hass),
    )

    users = {}
    users[entry.options.get(CONF_SIP_USER)] = entry.options.get(CONF_SIP_PASSWORD)
    server = MiniSIPServer(
        call_host=entry.options.get(CONF_SIP_CALLER_IP),
        users=users,
        port=int(entry.options.get(CONF_SIP_PORT)),
    )

    entry.runtime_data = SG150RuntimeData(
        server=server,
        client=client,
        integration=async_get_loaded_integration(hass, entry.domain),
        coordinator=coordinator,
    )

    await coordinator.async_config_entry_first_refresh()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    await server.start()

    setup_services(hass, entry=entry, server=server)

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: SG150ConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    await entry.runtime_data.server.stop()
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_reload_entry(
    hass: HomeAssistant,
    entry: SG150ConfigEntry,
) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)
