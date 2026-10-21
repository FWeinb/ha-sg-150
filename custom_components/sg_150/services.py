"""
Services provided by this integration.

The services are registered once per Home Assistant instance. Each call names
its gateway with `config_entry_id`, or omits it when exactly one gateway is
loaded. Errors are reported in the response data as `{"error": ...}`.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from homeassistant.components import media_source
from homeassistant.core import ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN,
    LOGGER,
)
from .line import LineError

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .line import Call, GatewayLine
    from .types import SG150Device


ATTR_CONFIG_ENTRY_ID = "config_entry_id"
BAD_REQUEST_START: int = 400


def resolve_line(hass: HomeAssistant, call: ServiceCall) -> GatewayLine:
    """Return the line of the gateway a service call targets, or raise ValueError."""
    entries = hass.config_entries.async_loaded_entries(DOMAIN)
    entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)

    if entry_id:
        for entry in entries:
            if entry.entry_id == entry_id:
                return entry.runtime_data.line
        msg = f"No loaded SG-150 gateway with config entry id: {entry_id}"
        raise ValueError(msg)

    if len(entries) == 1:
        return entries[0].runtime_data.line
    if not entries:
        msg = "No SG-150 gateway is loaded"
        raise ValueError(msg)
    msg = "Several SG-150 gateways are loaded, specify config_entry_id"
    raise ValueError(msg)


def _get_call(line: GatewayLine, call_id: str) -> Call:
    """Return the active call, or raise ValueError."""
    active = line.calls.get(call_id)
    if active is None:
        msg = f"There is currently no active call with call id: {call_id}"
        raise ValueError(msg)
    return active


def _device_summary(device: SG150Device | None) -> dict[str, str] | None:
    """Describe a call's device in a service response."""
    return {"id": device.id, "name": device.name} if device else None


def _optional(call: ServiceCall, response: ServiceResponse) -> ServiceResponse | None:
    """Return the response only when the caller asked for one."""
    return response if call.return_response else None


async def _fetch_media_source_audio(
    hass: HomeAssistant, media_source_id: str
) -> tuple[str, bytes]:
    """Resolve a generic Home Assistant media source and fetch its audio bytes."""
    resolved = await media_source.async_resolve_media(
        hass, media_source_id, target_media_player=None
    )
    # Always try local `path` first
    if resolved.path is not None:
        media_path = Path(resolved.path)
        if not await hass.async_add_executor_job(media_path.exists):
            msg = f"Resolved media path does not exist: {media_path}"
            raise ValueError(msg)

        LOGGER.debug("Got media path: '%s'", media_path)

        return resolved.mime_type, await hass.async_add_executor_job(
            media_path.read_bytes
        )

    # If non is found try resolved.url
    if not resolved.url:
        msg = "Media source did not resolve to a playable URL"
        raise ValueError(msg)

    session = async_get_clientsession(hass)

    async with session.get(resolved.url) as response:
        if response.status >= BAD_REQUEST_START:
            request_error = f"Media source request failed with status {response.status}"
            raise ValueError(request_error)

        return resolved.mime_type, await response.read()


async def handle_start_call(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    """Start a call through the gateway."""
    try:
        line = resolve_line(hass, call)
    except ValueError as err:
        return {"error": str(err)}

    if line.registration is None:
        return {"error": "Not Connected"}

    to_user = call.data.get("to", None)
    if not to_user:
        return {"error": "No phone number supplied"}

    try:
        started = await line.call(to_user)
    except LineError as err:
        return {"error": str(err)}

    return {"call_id": started.id, "error": None}


async def handle_stop_call(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse | None:
    """Hang up an active call."""
    call_id = call.data.get("call_id")
    if not call_id:
        return _optional(call, {"error": "No call_id supplied"})

    try:
        await _get_call(resolve_line(hass, call), call_id).hangup()
    except ValueError as err:
        return _optional(call, {"error": str(err)})
    return _optional(call, {"success": True, "error": None})


async def handle_send_sip_info_dtmf(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse | None:
    """Send a DTMF signal into an active call."""
    call_id = call.data.get("call_id")
    signal = call.data.get("signal")
    duration = call.data.get("duration") or "100"
    if not call_id or not signal:
        return _optional(call, {"error": "Missing mandatory call_id or signal"})

    try:
        await _get_call(resolve_line(hass, call), call_id).send_dtmf(signal, duration)
    except ValueError as err:
        return _optional(call, {"error": str(err)})
    return _optional(call, {"success": True, "error": None})


async def handle_play_audio(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse | None:
    """Send any media source audio to an active call."""
    call_id = call.data.get("call_id")
    if not call_id:
        return _optional(call, {"error": "Missing mandatory call_id"})

    media_source_id = call.data.get("media_source_id")
    if not media_source_id:
        return _optional(call, {"error": "Missing mandatory media_source_id"})

    try:
        active = _get_call(resolve_line(hass, call), call_id)
        LOGGER.debug("_fetch media for source_id=%s", media_source_id)
        mime_type, data = await _fetch_media_source_audio(hass, media_source_id)
        await active.play(mime_type, data)
    except ValueError as err:
        return _optional(call, {"error": str(err)})

    return _optional(call, {"success": True, "error": None})


async def handle_get_active_calls(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """List the active calls of the gateway."""
    try:
        line = resolve_line(hass, call)
    except ValueError as err:
        return {"active_calls": [], "calls": [], "error": str(err)}

    return {
        "active_calls": list(line.calls),
        "calls": [
            {
                "call_id": active.id,
                "direction": active.direction,
                "caller": _device_summary(active.caller),
                "callee": _device_summary(active.callee),
            }
            for active in line.calls.values()
        ],
    }


_SERVICES = {
    "start_call": (handle_start_call, SupportsResponse.ONLY),
    "stop_call": (handle_stop_call, SupportsResponse.OPTIONAL),
    "send_sip_info_dtmf": (handle_send_sip_info_dtmf, SupportsResponse.OPTIONAL),
    "get_active_calls": (handle_get_active_calls, SupportsResponse.ONLY),
    "play_audio": (handle_play_audio, SupportsResponse.OPTIONAL),
}


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the integration's services."""
    for name, (handler, supports_response) in _SERVICES.items():
        hass.services.async_register(
            DOMAIN, name, partial(handler, hass), supports_response=supports_response
        )
