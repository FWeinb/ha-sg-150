"""Component providing support for doorbell events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from aiortc import RTCIceServer
from homeassistant.components.camera import (
    Camera,
    CameraEntityCapabilities,
    CameraEntityFeature,
)
from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import (
    async_aiohttp_proxy_web,
    async_get_clientsession,
)
from homeassistant.helpers.httpx_client import get_async_client

from .const import CONF_TWO_WAY_AUDIO, LOGGER
from .entity import SG150DeviceEntity
from .line import CallEnded, CallStarted
from .talkback import Talkback

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from aiohttp import web
    from homeassistant.components.camera import WebRTCSendMessage
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback
    from webrtc_models import RTCIceCandidateInit

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .line import GatewayLine, LineEvent
    from .types import SG150Device


TIMEOUT = 5

# During testing, the first two frames of the stream are the "no stream" image.
# To avoid returning this, we wait for a few frames before returning a still image
FRAME_WAIT_COUNT = 3


async def async_setup_entry(
    _: HomeAssistant,
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary_sensor platform."""
    if entry.runtime_data.coordinator.data is None:
        LOGGER.warning("Coordinator data is None, skipping binary_sensor setup")
        return

    # Create an entity for each device with an MJPEG stream
    async_add_entities(
        SG150Camera(
            coordinator=entry.runtime_data.coordinator,
            device=device,
            url=url,
            line=entry.runtime_data.line,
            two_way_audio=entry.options.get(CONF_TWO_WAY_AUDIO, False),
        )
        for device in entry.runtime_data.coordinator.data.devices
        if (url := device.mjpeg_stream_url) is not None
    )


async def _mjpeg_frames(stream: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Split an MJPEG stream into its JPEG frames."""
    data = b""

    async for chunk in stream:
        data += chunk

        while True:
            jpg_start = data.find(b"\xff\xd8")
            if jpg_start == -1:
                data = data[-1:]
                break

            jpg_end = data.find(b"\xff\xd9", jpg_start + 2)
            if jpg_end == -1:
                if jpg_start:
                    data = data[jpg_start:]
                break

            yield data[jpg_start : jpg_end + 2]
            data = data[jpg_end + 2 :]


async def _async_extract_image_from_mjpeg(
    stream: AsyncIterator[bytes],
) -> bytes | None:
    """
    Take in MJPEG stream and extract a frame from it.

    The first FRAME_WAIT_COUNT frames are ignored, as they are usually the "no stream"
    image.
    """
    frame_count = 0
    async for frame in _mjpeg_frames(stream):
        frame_count += 1
        if frame_count >= FRAME_WAIT_COUNT:
            return frame

    return None


class SG150Camera(SG150DeviceEntity, Camera):  # pylint: disable=abstract-method
    """
    Camera Entity for SG150 Stream.

    With two-way audio enabled, the live view is WebRTC (see talkback.py) and
    carries the door station's call audio both ways; otherwise it is MJPEG.
    """

    # This is how the camera entity is calculating this value:
    # https://github.com/home-assistant/core/blob/7bddee43e85bc13ea3218be8b34848c77ade4969/homeassistant/components/generic/camera.py#L106
    _attr_frame_interval = 1 / 15

    def __init__(
        self,
        coordinator: SG150Coordinator,
        device: SG150Device,
        url: str,
        line: GatewayLine,
        *,
        two_way_audio: bool = False,
    ) -> None:
        """Initialize the camera entity."""
        # CoordinatorEntity does not chain to Camera.__init__, so call both.
        super().__init__(coordinator, device, key="camera")
        Camera.__init__(self)
        self._stream_url = url
        self._line = line
        self._attr_is_streaming = False
        self._two_way_audio = two_way_audio
        self._talkback: Talkback | None = None
        if two_way_audio:
            # Fixed for the entity's lifetime: the frontend reads capabilities
            # once when the live view opens, so they can't follow call state.
            self._attr_supported_features = CameraEntityFeature.STREAM
            self._attr_camera_entity_capabilities = CameraEntityCapabilities(
                two_way_audio=True
            )

    def _update_call_state(self) -> None:
        """Stream while a call to or from this device is established."""
        self._attr_is_streaming = any(
            call.involves(self._device_id) for call in self._line.calls.values()
        )

    def _on_line_event(self, event: LineEvent) -> None:
        """Update the camera state when a call starts or ends."""
        if isinstance(event, (CallStarted, CallEnded)):
            self._update_call_state()
            self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Subscribe to line events."""
        self.async_on_remove(self._line.subscribe(self._on_line_event))
        await super().async_added_to_hass()
        self._update_call_state()
        if self._two_way_audio:
            self._talkback = Talkback(self._line, self._device_id, self._jpegs)

    async def async_will_remove_from_hass(self) -> None:
        """Close the WebRTC sessions."""
        await super().async_will_remove_from_hass()
        if self._talkback is not None:
            await self._talkback.close()
            self._talkback = None

    async def _jpegs(self) -> AsyncIterator[bytes]:
        """Yield the JPEG frames of the camera's MJPEG stream."""
        client = get_async_client(self.hass)
        async with client.stream("get", self._stream_url, timeout=TIMEOUT) as stream:
            async for frame in _mjpeg_frames(stream.aiter_raw()):
                yield frame

    async def async_handle_async_webrtc_offer(
        self, offer_sdp: str, session_id: str, send_message: WebRTCSendMessage
    ) -> None:
        """Answer a WebRTC offer from the frontend."""
        if self._talkback is None:
            msg = "Two-way audio is not enabled for this gateway"
            raise HomeAssistantError(msg)
        configuration = self.async_get_webrtc_client_configuration().configuration
        ice_servers = [
            RTCIceServer(
                urls=server.urls,
                username=server.username,
                credential=server.credential,
            )
            for server in configuration.ice_servers
        ]
        try:
            await self._talkback.handle_offer(
                session_id, offer_sdp, send_message, ice_servers
            )
        except Exception as err:
            msg = f"Could not answer the WebRTC offer: {err}"
            raise HomeAssistantError(msg) from err

    async def async_on_webrtc_candidate(
        self, session_id: str, candidate: RTCIceCandidateInit
    ) -> None:
        """Handle a WebRTC candidate from the frontend."""
        if self._talkback is None:
            msg = "Two-way audio is not enabled for this gateway"
            raise HomeAssistantError(msg)
        try:
            await self._talkback.add_candidate(
                session_id,
                candidate.candidate,
                candidate.sdp_mid,
                candidate.sdp_m_line_index,
            )
        except (ValueError, TimeoutError) as err:
            raise HomeAssistantError(str(err)) from err

    @callback
    def close_webrtc_session(self, session_id: str) -> None:
        """Close a WebRTC session, hanging up if it was the last one talking."""
        super().close_webrtc_session(session_id)
        if self._talkback is not None:
            self.hass.async_create_task(
                self._talkback.close_session(session_id),
                f"sg_150 camera {self.entity_id} close WebRTC session",
            )

    async def stream_source(self) -> str:
        """Return the stream source, also used by HomeKit to support MJEPG streams."""
        return self._stream_url

    async def async_camera_image(
        self,
        width: int | None = None,  # noqa: ARG002
        height: int | None = None,  # noqa: ARG002
    ) -> bytes | None:
        """Return a still image response from the camera."""
        try:
            client = get_async_client(self.hass)
            async with client.stream(
                "get", self._stream_url, timeout=TIMEOUT
            ) as stream:
                return await _async_extract_image_from_mjpeg(stream.aiter_raw())

        except TimeoutError:
            LOGGER.error("Timeout getting camera image from %s", self.name)

        except httpx.HTTPError as err:
            LOGGER.error("Error getting new camera image from %s: %s", self.name, err)

        return None

    async def handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse | None:
        """Serve an HTTP MJPEG stream from the camera."""
        websession = async_get_clientsession(self.hass)
        stream_coro = websession.get(self._stream_url)
        # This will still flash the "no stream" image for a few frames,
        # but it will eventually return the actual stream.
        # This could be solved by implementing a custom MJPEG proxy that filters
        # out the first few frames, but that would be more complex.
        return await async_aiohttp_proxy_web(self.hass, request, stream_coro)
