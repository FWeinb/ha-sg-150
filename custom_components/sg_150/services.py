"""
Services provided by this integration.

The services are registered once per Home Assistant instance. Each call names
its gateway with `config_entry_id`, or omits it when exactly one gateway is
loaded. Invalid input is rejected by the service schemas. Other errors are
reported in the response data as `{"error": ...}` when the caller asked for a
response, and raised as HomeAssistantError otherwise.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp
import voluptuous as vol
from homeassistant.components import media_source
from homeassistant.components.media_player import async_process_play_media_url
from homeassistant.core import ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
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
# Media for play_audio is downloaded and decoded in memory, so it is limited.
MAX_AUDIO_BYTES = 10 * 1024 * 1024
DOWNLOAD_TIMEOUT = aiohttp.ClientTimeout(total=30)

# Dial strings and DTMF signals end up in SIP headers and bodies.
_DIAL_STRING = vol.All(cv.string, vol.Upper, vol.Match(r"^[0-9*#A-D]+$"))
_ENTRY = {vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string}
_CALL = {vol.Required("call_id"): cv.string, **_ENTRY}


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


def _failed(call: ServiceCall, error: Exception) -> ServiceResponse:
    """Report an error as response data, or raise it when none was asked for."""
    if call.return_response:
        return {"error": str(error)}
    raise HomeAssistantError(str(error)) from error


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

        if (await hass.async_add_executor_job(media_path.stat)).st_size > (
            MAX_AUDIO_BYTES
        ):
            msg = f"Media file is larger than {MAX_AUDIO_BYTES} bytes: {media_path}"
            raise ValueError(msg)
        return resolved.mime_type, await hass.async_add_executor_job(
            media_path.read_bytes
        )

    # If non is found try resolved.url
    if not resolved.url:
        msg = "Media source did not resolve to a playable URL"
        raise ValueError(msg)

    # Relative URLs, such as from TTS, are made absolute and signed.
    url = async_process_play_media_url(hass, resolved.url)
    try:
        return resolved.mime_type, await _download(hass, url)
    except (aiohttp.ClientError, TimeoutError) as err:
        msg = f"Could not download the media: {err!r}"
        raise ValueError(msg) from err


async def _download(hass: HomeAssistant, url: str) -> bytes:
    """Download `url`, refusing more than MAX_AUDIO_BYTES."""
    session = async_get_clientsession(hass)
    async with session.get(url, timeout=DOWNLOAD_TIMEOUT) as response:
        if response.status >= BAD_REQUEST_START:
            request_error = f"Media source request failed with status {response.status}"
            raise ValueError(request_error)

        data = bytearray()
        async for chunk in response.content.iter_chunked(64 * 1024):
            data += chunk
            if len(data) > MAX_AUDIO_BYTES:
                msg = f"Media is larger than {MAX_AUDIO_BYTES} bytes"
                raise ValueError(msg)
        return bytes(data)


async def handle_start_call(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    """Start a call through the gateway."""
    try:
        line = resolve_line(hass, call)
    except ValueError as err:
        return {"error": str(err)}

    if line.registration is None:
        return {"error": "Not Connected"}

    try:
        started = await line.call(call.data["to"])
    except LineError as err:
        return {"error": str(err)}

    return {"call_id": started.id, "error": None}


async def handle_stop_call(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse | None:
    """Hang up an active call."""
    try:
        await _get_call(resolve_line(hass, call), call.data["call_id"]).hangup()
    except ValueError as err:
        return _failed(call, err)
    return _optional(call, {"success": True, "error": None})


async def handle_send_sip_info_dtmf(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse | None:
    """Send a DTMF signal into an active call."""
    try:
        await _get_call(resolve_line(hass, call), call.data["call_id"]).send_dtmf(
            call.data["signal"], str(call.data["duration"])
        )
    except ValueError as err:
        return _failed(call, err)
    return _optional(call, {"success": True, "error": None})


async def handle_play_audio(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse | None:
    """Send any media source audio to an active call."""
    media_source_id = call.data["media_source_id"]
    try:
        active = _get_call(resolve_line(hass, call), call.data["call_id"])
        LOGGER.debug("_fetch media for source_id=%s", media_source_id)
        mime_type, data = await _fetch_media_source_audio(hass, media_source_id)
        await active.play(mime_type, data)
    except (ValueError, HomeAssistantError) as err:  # Unresolvable media too
        return _failed(call, err)

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
    "start_call": (
        handle_start_call,
        SupportsResponse.ONLY,
        vol.Schema({vol.Required("to"): _DIAL_STRING, **_ENTRY}),
    ),
    "stop_call": (handle_stop_call, SupportsResponse.OPTIONAL, vol.Schema(_CALL)),
    "send_sip_info_dtmf": (
        handle_send_sip_info_dtmf,
        SupportsResponse.OPTIONAL,
        vol.Schema(
            {
                **_CALL,
                vol.Required("signal"): _DIAL_STRING,
                vol.Optional("duration", default=100): vol.All(
                    vol.Coerce(int), vol.Range(min=1)
                ),
            }
        ),
    ),
    "get_active_calls": (
        handle_get_active_calls,
        SupportsResponse.ONLY,
        vol.Schema(_ENTRY),
    ),
    "play_audio": (
        handle_play_audio,
        SupportsResponse.OPTIONAL,
        vol.Schema({**_CALL, vol.Required("media_source_id"): cv.string}),
    ),
}


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the integration's services."""
    for name, (handler, supports_response, schema) in _SERVICES.items():
        hass.services.async_register(
            DOMAIN,
            name,
            partial(handler, hass),
            schema=schema,
            supports_response=supports_response,
        )
