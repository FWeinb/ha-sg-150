"""Component providing support for doorbell events."""

from __future__ import annotations

import json
import collections
import httpx

from typing import TYPE_CHECKING

from homeassistant.core import HomeAssistant, callback
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.aiohttp_client import (
    async_aiohttp_proxy_web,
    async_get_clientsession,
)

from .entity import SG150BaseDeviceEntity
from .const import LOGGER, MANUFACTURER, CONF_HOST_ADDRESS
from .helpers import is_door, has_video_sender, has_video_extraction, get_video_extraction_capability
from .types import SG150Device

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from .data import SG150ConfigEntry
    from .coordinator import SG150Coordinator


TIMEOUT = 10
BUFFER_SIZE = 102400


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001 Unused function argument: `hass`
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary_sensor platform."""
    if entry.runtime_data.coordinator.data is None:
        LOGGER.warn("Coordinator data is None, skipping binary_sensor setup")
        return

    entites = []

    # Create an entity for each device in `data`
    for device in entry.runtime_data.coordinator.data.devices:
        if (has_video_extraction(device)):
            extractor = get_video_extraction_capability(device)
            if (extractor.properties.type == "MJPEG_STREAM"):
                entites.append(
                    SG150Camera(
                        coordinator=entry.runtime_data.coordinator,
                        device=device,
                        url=extractor.properties.url
                    )
                )

    async_add_entities(entites)


async def async_extract_image_from_mjpeg(stream: AsyncIterator[bytes]) -> bytes | None:
    """Take in a MJPEG stream object, return the jpg from it."""
    data = b""

    async for chunk in stream:
        data += chunk
        jpg_end = data.find(b"\xff\xd9")

        if jpg_end == -1:
            continue

        jpg_start = data.find(b"\xff\xd8")

        if jpg_start == -1:
            continue

        return data[jpg_start: jpg_end + 2]

    return None


class SG150Camera(Camera):

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device, url: str) -> None:
        """Initialize the doorbell event entity."""
        super().__init__()
        self._mjpeg_url = url
        self._attr_unique_id = device.id + "Camera"
        self._attr_name = f"{coordinator.get_enity_name_for_device(device)} Camera"
        self._attr_device_info = DeviceInfo(
            identifiers={(coordinator.config_entry.domain, device.id)},
            name=device.name,
            manufacturer=MANUFACTURER,
            via_device=coordinator.get_gateway_identifier()
        )

    async def stream_source(self) -> str:
        """Return the stream source."""
        return self._mjpeg_url

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image response from the camera."""
        try:
            client = get_async_client(self.hass)
            async with client.stream(
                "get", self._mjpeg_url, timeout=TIMEOUT
            ) as stream:
                return await async_extract_image_from_mjpeg(
                    stream.aiter_bytes(BUFFER_SIZE)
                )

        except TimeoutError:
            LOGGER.error("Timeout getting camera image from %s", self.name)

        except httpx.HTTPError as err:
            LOGGER.error(
                "Error getting new camera image from %s: %s", self.name, err)

        return None

    async def handle_async_mjpeg_stream(
        self, request: web.Request
    ) -> web.StreamResponse | None:
        websession = async_get_clientsession(self.hass)
        stream_coro = websession.get(self._mjpeg_url)
        return await async_aiohttp_proxy_web(self.hass, request, stream_coro)
