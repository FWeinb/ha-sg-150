"""
Media source with the pictures the gateway stores during calls.

Browsing goes gateway -> PBX phone -> images, skipping the gateway level when only
one gateway is loaded.

The gateway needs a bearer token for the images.
Doing that via an authenticated Home Assistant view endpoint is the easiest way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.components.media_player import BrowseError, MediaClass
from homeassistant.components.media_source import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
    Unresolvable,
)
from homeassistant.config_entries import ConfigEntryState
from homeassistant.util import dt as dt_util

from .api import SG150ApiClientError
from .const import DOMAIN, LOGGER
from .types import SG150Device, SG150DeviceType

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import SG150ConfigEntry


IMAGE_URL = "/api/sg_150/image/{entry_id}/{uid}"
IMAGE_MIME_TYPE = "image/jpeg"


async def async_get_media_source(hass: HomeAssistant) -> MediaSource:
    """Set up the SG-150 media source."""
    hass.http.register_view(SG150ImageView(hass))
    return SG150MediaSource(hass)


def _image_url(entry_id: str, uid: str) -> str:
    return IMAGE_URL.format(entry_id=entry_id, uid=uid)


def _image_devices(entry: SG150ConfigEntry) -> list[SG150Device]:
    """Return the devices the gateway stores images for: its PBX phones."""
    return [
        device
        for device in entry.runtime_data.coordinator.data.devices
        if device.type == SG150DeviceType.PBXPHONE
    ]


def _loaded_entry(hass: HomeAssistant, entry_id: str) -> SG150ConfigEntry | None:
    entry = hass.config_entries.async_get_entry(entry_id)
    if entry is None or entry.domain != DOMAIN:
        return None
    if entry.state is not ConfigEntryState.LOADED:
        return None
    return entry


def _directory(
    identifier: str | None, title: str, *, children: list[BrowseMediaSource]
) -> BrowseMediaSource:
    return BrowseMediaSource(
        domain=DOMAIN,
        identifier=identifier,
        media_class=MediaClass.DIRECTORY,
        media_content_type="",
        title=title,
        can_play=False,
        can_expand=True,
        children_media_class=MediaClass.DIRECTORY,
        children=children,
    )


class SG150MediaSource(MediaSource):
    """Pictures taken by the door stations during calls."""

    name = "Siedle Gateway"

    def __init__(self, hass: HomeAssistant) -> None:
        """Create the media source."""
        super().__init__(DOMAIN)
        self.hass = hass

    async def async_resolve_media(self, item: MediaSourceItem) -> PlayMedia:
        """Resolve an image to the URL of the proxy view."""
        parts = (item.identifier or "").split("/")
        if len(parts) != 3:  # noqa: PLR2004
            msg = f"Unknown SG-150 media item: {item.identifier}"
            raise Unresolvable(msg)
        entry_id, _, uid = parts
        return PlayMedia(_image_url(entry_id, uid), IMAGE_MIME_TYPE)

    async def async_browse_media(self, item: MediaSourceItem) -> BrowseMediaSource:
        """Browse gateways, their devices and the devices' images."""
        parts = item.identifier.split("/") if item.identifier else []

        if not parts:
            entries = self.hass.config_entries.async_loaded_entries(DOMAIN)
            if len(entries) == 1:
                return self._browse_entry(entries[0], identifier=None)
            return _directory(
                None,
                self.name,
                children=[
                    _directory(entry.entry_id, entry.title, children=[])
                    for entry in entries
                ],
            )

        entry = _loaded_entry(self.hass, parts[0])
        if entry is None:
            msg = f"SG-150 gateway is not loaded: {parts[0]}"
            raise BrowseError(msg)

        if len(parts) == 1:
            return self._browse_entry(entry, identifier=entry.entry_id)
        if len(parts) == 2:  # noqa: PLR2004
            return await self._browse_device(entry, parts[1])

        msg = f"Unknown SG-150 media item: {item.identifier}"
        raise BrowseError(msg)

    def _browse_entry(
        self, entry: SG150ConfigEntry, identifier: str | None
    ) -> BrowseMediaSource:
        """List the devices that have stored images."""
        devices = _image_devices(entry)
        return _directory(
            identifier,
            entry.title,
            children=[
                _directory(f"{entry.entry_id}/{device.id}", device.name, children=[])
                for device in devices
            ],
        )

    async def _browse_device(
        self, entry: SG150ConfigEntry, device_id: str
    ) -> BrowseMediaSource:
        """List a device's stored images, newest first."""
        device = self._device(entry, device_id)
        try:
            images = await entry.runtime_data.client.async_get_stored_images(device_id)
        except SG150ApiClientError as err:
            msg = f"Could not load the images of {device.name}: {err}"
            raise BrowseError(msg) from err

        images.sort(key=lambda image: image.timestamp, reverse=True)
        node = _directory(f"{entry.entry_id}/{device_id}", device.name, children=[])
        node.children_media_class = MediaClass.IMAGE
        node.children = [
            BrowseMediaSource(
                domain=DOMAIN,
                identifier=f"{entry.entry_id}/{device_id}/{image.uid}",
                media_class=MediaClass.IMAGE,
                media_content_type=IMAGE_MIME_TYPE,
                title=(
                    f"{image.cameraName} "
                    f"{dt_util.as_local(image.timestamp):%Y-%m-%d %H:%M:%S}"
                ),
                can_play=True,
                can_expand=False,
                thumbnail=_image_url(entry.entry_id, image.uid),
            )
            for image in images
        ]
        return node

    @staticmethod
    def _device(entry: SG150ConfigEntry, device_id: str) -> SG150Device:
        for device in _image_devices(entry):
            if device.id == device_id:
                return device
        msg = f"Unknown SG-150 device: {device_id}"
        raise BrowseError(msg)


class SG150ImageView(HomeAssistantView):
    """Serve stored gateway images to authenticated Home Assistant users."""

    url = IMAGE_URL
    name = "api:sg_150:image"

    def __init__(self, hass: HomeAssistant) -> None:
        """Create the view."""
        self.hass = hass

    async def get(self, _: web.Request, entry_id: str, uid: str) -> web.Response:
        """Fetch the image from the gateway and pass it on."""
        entry = _loaded_entry(self.hass, entry_id)
        if entry is None:
            raise web.HTTPNotFound

        try:
            body, content_type = await entry.runtime_data.client.async_get_stored_image(
                uid
            )
        except SG150ApiClientError as err:
            LOGGER.warning("Could not load stored image %s: %s", uid, err)
            raise web.HTTPBadGateway from err

        return web.Response(
            body=body,
            content_type=content_type or IMAGE_MIME_TYPE,
            headers={"Cache-Control": "private, max-age=86400"},
        )
