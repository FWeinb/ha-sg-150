"""Component providing support for doorbell events."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from homeassistant.components.camera import Camera
from homeassistant.helpers.aiohttp_client import (
    async_aiohttp_proxy_web,
    async_get_clientsession,
)
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.httpx_client import get_async_client

from .const import LOGGER, MANUFACTURER
from .helpers import (
    get_video_extraction_capability,
    has_video_extraction,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from aiohttp import web
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .sip.minisip import MiniSIPServer
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
        if has_video_extraction(device):
            extractor = get_video_extraction_capability(device)
            if extractor.properties.type == "MJPEG_STREAM":
                entites.append(
                    SG150Camera(
                        coordinator=entry.runtime_data.coordinator,
                        device=device,
                        url=extractor.properties.url,
                        minisip=entry.runtime_data.server,
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


class SG150Camera(Camera):  # pylint: disable=abstract-method
    """Camera Entity for SG150 Stream."""

    _attr_has_entity_name = True
    _attr_translation_key = "camera"

    # This is how the camera entity is calculating this value:
    # https://github.com/home-assistant/core/blob/7bddee43e85bc13ea3218be8b34848c77ade4969/homeassistant/components/generic/camera.py#L106
    _attr_frame_interval = 1 / 15

    def __init__(
        self,
        coordinator: SG150Coordinator,
        device: SG150Device,
        url: str,
        minisip: MiniSIPServer,
    ) -> None:
        """Initialize the doorbell event entity."""
        super().__init__()
        self._stream_url = url
        self._minisip = minisip
        self._attr_is_streaming = False
        self._attr_unique_id = device.id + "Camera"
        self._attr_device_info = DeviceInfo(
            identifiers={(coordinator.config_entry.domain, device.id)},
            name=device.name,
            manufacturer=MANUFACTURER,
            via_device=coordinator.get_gateway_identifier(),
        )

    async def _async_update_call_state(self, *_: object) -> None:
        """Update the camera state when a SIP call starts or ends."""
        # Assume this camera is active when there is any active call
        # technically we would need to check if there is a call to this specific camera
        # but i don't have the info here yet...
        self._attr_is_streaming = bool(self._minisip.active_calls)
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register for SIP call state changes."""
        self.async_on_remove(
            self._minisip.add_listener(
                "on_call_established", self._async_update_call_state
            )
        )
        self.async_on_remove(
            self._minisip.add_listener("on_call_ended", self._async_update_call_state)
        )
        await super().async_added_to_hass()
        await self._async_update_call_state()

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
