"""Services provided by this integration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.core import ServiceCall, ServiceResponse, SupportsResponse, callback

from .const import (
    CONF_SIP_NUMBER,
    CONF_SIP_USER,
    DOMAIN,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import SG150ConfigEntry
    from .sip.minisip import MiniSIPServer


def setup_services(
    hass: HomeAssistant, entry: SG150ConfigEntry, server: MiniSIPServer
) -> None:
    """Setups the HA services."""

    @callback
    async def handle_start_call(call: ServiceCall) -> ServiceResponse | None:
        """Handle the start call."""
        registration = server.registrations.get(entry.options.get(CONF_SIP_USER))
        if not registration:
            return {"error": "Not Connected"}

        to_user = call.data.get("to", None)
        if not to_user:
            return {"error": "No phone number supplied"}

        call_id, _ = await server.send_invite(
            target_addr=registration.get("addr"),
            from_user=entry.options.get(CONF_SIP_NUMBER),
            to_user=to_user,
        )

        if not call_id:
            return {"error": f"Could not start call to {to_user}"}

        return {"call_id": call_id, "error": None}

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
