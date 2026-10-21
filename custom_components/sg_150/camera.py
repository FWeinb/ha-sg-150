"""Component providing support for doorbell events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from homeassistant.components.camera import Camera
from homeassistant.helpers.aiohttp_client import (
    async_aiohttp_proxy_web,
    async_get_clientsession,
)
from homeassistant.helpers.httpx_client import get_async_client

from .const import LOGGER
from .entity import SG150DeviceEntity
from .line import CallEnded, CallStarted

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from aiohttp import web
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

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

    entites = []

    # Create an entity for each device in `data`
    for device in entry.runtime_data.coordinator.data.devices:
        video_extraction = device.video_extraction
        if video_extraction is not None and video_extraction.type == "MJPEG_STREAM":
            entites.append(
                SG150Camera(
                    coordinator=entry.runtime_data.coordinator,
                    device=device,
                    url=video_extraction.url,
                    line=entry.runtime_data.line,
                )
            )

    async_add_entities(entites)


async def _async_extract_image_from_mjpeg(
    stream: AsyncIterator[bytes],
) -> bytes | None:
    """
    Take in MJPEG stream and extract a frame from it.

    The first FRAME_WAIT_COUNT frames are ignored, as they are usually the "no stream"
    image.
    """
    data = b""
    frame_count = 0

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

            frame = data[jpg_start : jpg_end + 2]
            data = data[jpg_end + 2 :]

            frame_count += 1

            if frame_count >= FRAME_WAIT_COUNT:
                return frame

    return None


class SG150Camera(SG150DeviceEntity, Camera):  # pylint: disable=abstract-method
    """Camera Entity for SG150 Stream."""

    # This is how the camera entity is calculating this value:
    # https://github.com/home-assistant/core/blob/7bddee43e85bc13ea3218be8b34848c77ade4969/homeassistant/components/generic/camera.py#L106
    _attr_frame_interval = 1 / 15

    def __init__(
        self,
        coordinator: SG150Coordinator,
        device: SG150Device,
        url: str,
        line: GatewayLine,
    ) -> None:
        """Initialize the camera entity."""
        # CoordinatorEntity does not chain to Camera.__init__, so call both.
        super().__init__(coordinator, device, key="camera")
        Camera.__init__(self)
        self._stream_url = url
        self._line = line
        self._attr_is_streaming = False

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
