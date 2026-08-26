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

    @callback
    async def handle_send_sip_info_dtmf(call: ServiceCall) -> None:
        """Handle the DTMF signal call."""
        call_id = call.data.get("call_id")
        signal = call.data.get("signal")
        duration = call.data.get("duration") or "100"
        if call_id and signal:
            await server.send_sip_info_dtmf(call_id, signal, duration)

    @callback
    async def handle_get_active_calls(_: ServiceCall) -> ServiceResponse:
        """Handle the get active calls service."""
        # get all keys from the server's active_calls dictionary
        active_calls = list(server.active_calls.keys())
        return {"active_calls": active_calls}

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
    hass.services.async_register(
        DOMAIN,
        "send_sip_info_dtmf",
        handle_send_sip_info_dtmf,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_active_calls",
        handle_get_active_calls,
        supports_response=SupportsResponse.ONLY,
    )
