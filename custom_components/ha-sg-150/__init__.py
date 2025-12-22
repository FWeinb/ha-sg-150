"""
Custom integration to integrate ha-sg-150 with Home Assistant.

For more details about this integration, please refer to
https://github.com/fweinb/ha-sg-150
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from homeassistant.core import ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.loader import async_get_loaded_integration

from .sip.minisip import MiniSIPServer
from .api import SG150ApiClient
from .const import (
    DOMAIN,
    LOGGER,
    API_PORT,
    CONF_HOST_ADDRESS,
    CONF_SIP_CALLER_IP,
    CONF_SIP_USER,
    CONF_SIP_PASSWORD,
    CONF_SIP_PORT,
    CONF_SIP_NUMBER
)
from .coordinator import SG150Coordinator
from .data import SG150RuntimeData

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from .data import SG150ConfigEntry

PLATFORMS: list[Platform] = [
    Platform.EVENT,
    Platform.CAMERA,
    Platform.SENSOR,
    Platform.BINARY_SENSOR
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SG150ConfigEntry,
) -> bool:
    """Set up this integration using UI."""
    coordinator = SG150Coordinator(
        hass=hass,
        logger=LOGGER,
        name=DOMAIN,
        update_interval=timedelta(seconds=30),
    )

    client = SG150ApiClient(
        host_address=entry.data.get(CONF_HOST_ADDRESS),
        port=API_PORT,
        username=entry.data.get(CONF_USERNAME),
        password=entry.data.get(CONF_PASSWORD),
        session=async_get_clientsession(hass),
    )

    users = {}
    users[entry.options.get(CONF_SIP_USER)] = entry.options.get(
        CONF_SIP_PASSWORD)
    server = MiniSIPServer(
        call_host=entry.options.get(CONF_SIP_CALLER_IP),
        users=users,
        port=entry.options.get(CONF_SIP_PORT)
    )

    entry.runtime_data = SG150RuntimeData(
        server=server,
        client=client,
        integration=async_get_loaded_integration(hass, entry.domain),
        coordinator=coordinator
    )

    await coordinator.async_config_entry_first_refresh()
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(
        entry.add_update_listener(async_reload_entry)
    )

    await server.start()

    @callback
    async def handle_start_call(call: ServiceCall) -> ServiceResponse | None:
        """Handle the service action call."""
        addr = server.registrations.get(entry.options.get(CONF_SIP_USER))
        if not addr:
            return {"error": "Not Connected"}
        to_user = call.data.get("to", "*213")
        call_id, _ = await server.send_invite(
            target_addr=server.registrations.get(
                entry.options.get(CONF_SIP_USER)),
            from_user=entry.options.get(CONF_SIP_NUMBER),
            to_user=to_user
        )
        return {
            "call_id": call_id,
            "error": None
        }

    @callback
    async def handle_stop_call(call: ServiceCall) -> None:
        """Handle the service action call."""
        call_id = call.data.get("call_id")
        if call_id:
            await server.send_bye(call_id)

    hass.services.async_register(
        DOMAIN,
        "start_call",
        handle_start_call,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "stop_call",
        handle_stop_call,
        supports_response=SupportsResponse.NONE,
    )

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
