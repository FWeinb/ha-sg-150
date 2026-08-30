"""Services provided by this integration."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from homeassistant.components import media_source
from homeassistant.core import ServiceCall, ServiceResponse, SupportsResponse, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_SIP_NUMBER,
    CONF_SIP_USER,
    DOMAIN,
    LOGGER,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import SG150ConfigEntry
    from .sip.minisip import MiniSIPServer


BAD_REQUEST_START: int = 400


def setup_services(  # noqa: PLR0915
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
    async def handle_stop_call(call: ServiceCall) -> ServiceResponse | None:
        """Handle the service action call."""
        call_id = call.data.get("call_id")
        if call_id:
            try:
                await server.send_bye(call_id)
            except ValueError as e:
                return {"error": str(e)} if call.return_response else None
            return {"success": True, "error": None} if call.return_response else None

        return {"error": "No call_id supplied"} if call.return_response else None

    @callback
    async def handle_send_sip_info_dtmf(call: ServiceCall) -> ServiceResponse | None:
        """Handle the DTMF signal call."""
        call_id = call.data.get("call_id")
        signal = call.data.get("signal")
        duration = call.data.get("duration") or "100"
        if call_id and signal:
            try:
                await server.send_sip_info_dtmf(call_id, signal, duration)
            except ValueError as e:
                return {"error": str(e)} if call.return_response else None
            return {"success": True, "error": None} if call.return_response else None

        return (
            {"error": "Missing mandatory call_id or signal"}
            if call.return_response
            else None
        )

    async def _fetch_media_source_audio(media_source_id: str) -> tuple[str, bytes]:
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
                request_error = (
                    f"Media source request failed with status {response.status}"
                )
                raise ValueError(request_error)

            return resolved.mime_type, await hass.async_add_executor_job(response.read)

    @callback
    async def handle_play_audio(call: ServiceCall) -> ServiceResponse | None:
        """Send any media source audio to the active call."""
        call_id = call.data.get("call_id")
        if not call_id:
            return (
                {"error": "Missing mandatory call_id"} if call.return_response else None
            )

        media_source_id = call.data.get("media_source_id")
        if not media_source_id:
            return (
                {"error": "Missing mandatory media_source_id"}
                if call.return_response
                else None
            )

        try:
            LOGGER.debug("_fetch media for source_id=%s", media_source_id)
            mime_type, data = await _fetch_media_source_audio(media_source_id)
            await server.play_audio(call_id, mime_type, data)
        except ValueError as err:
            return {"error": str(err)} if call.return_response else None

        return {"success": True, "error": None} if call.return_response else None

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
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(
        DOMAIN,
        "send_sip_info_dtmf",
        handle_send_sip_info_dtmf,
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(
        DOMAIN,
        "get_active_calls",
        handle_get_active_calls,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "play_audio",
        handle_play_audio,
        supports_response=SupportsResponse.OPTIONAL,
    )
