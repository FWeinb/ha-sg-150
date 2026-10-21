"""The media source with the gateway's stored call images."""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import TYPE_CHECKING

import pytest
from homeassistant.components import media_source
from homeassistant.components.media_player import BrowseError
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util

from custom_components.sg_150.const import DOMAIN
from tests.conftest import API_URL
from tests.utils import FIXTURES

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant_custom_component.common import MockConfigEntry
    from pytest_homeassistant_custom_component.test_util.aiohttp import (
        AiohttpClientMocker,
    )
    from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

RESPONSE = json.loads((FIXTURES / "image_store_images.json").read_text())
IMAGES = RESPONSE["images"]
NEWEST, OLDEST = IMAGES[1], IMAGES[0]
JPEG = b"\xff\xd8 front door \xff\xd9"


def title(image: dict) -> str:
    """Return the title the media source gives an image."""
    taken = dt_util.as_local(datetime.fromisoformat(image["timestamp"]))
    return f"{image['cameraName']} {taken:%Y-%m-%d %H:%M:%S}"


@pytest.fixture(autouse=True)
async def media_source_loaded(
    hass: HomeAssistant,
    gateway_api: AiohttpClientMocker,
    setup_integration: None,
) -> None:
    """Set up the integration with stored images, then the media source."""
    gateway_api.get(
        f"{API_URL}/video/imageStore/images",
        params={"deviceId": "pbx-external"},
        json=RESPONSE,
    )
    gateway_api.get(
        f"{API_URL}/video/imageStore/images",
        params={"deviceId": "pbx-internal-phone"},
        json=IMAGES,
    )
    gateway_api.get(
        f"{API_URL}/video/imageStore/images/{NEWEST['uid']}",
        json={**NEWEST, "content": base64.b64encode(JPEG).decode()},
    )
    gateway_api.get(
        f"{API_URL}/video/imageStore/images/{OLDEST['uid']}",
        json={**OLDEST, "content": ""},
    )
    assert await async_setup_component(hass, "media_source", {})
    await hass.async_block_till_done()


async def test_root_lists_pbx_phones(hass: HomeAssistant) -> None:
    """With one gateway the root lists its PBX phones, the only image owners."""
    root = await media_source.async_browse_media(hass, f"media-source://{DOMAIN}")

    assert [child.title for child in root.children] == [
        "Home Assistant",
        "Kitchen Phone",
    ]


async def test_other_devices_cannot_be_browsed(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """Door stations and other non-PBX devices have no image folder."""
    with pytest.raises(BrowseError):
        await media_source.async_browse_media(
            hass, f"media-source://{DOMAIN}/{config_entry.entry_id}/door-front"
        )


async def test_device_lists_its_images_newest_first(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """A device folder holds its stored images with thumbnails."""
    entry_id = config_entry.entry_id
    folder = await media_source.async_browse_media(
        hass, f"media-source://{DOMAIN}/{entry_id}/pbx-external"
    )

    assert [child.title for child in folder.children] == [
        title(NEWEST),
        title(OLDEST),
    ]
    newest = folder.children[0]
    assert newest.media_content_id == (
        f"media-source://{DOMAIN}/{entry_id}/pbx-external/{NEWEST['uid']}"
    )
    assert newest.can_play
    assert newest.thumbnail == f"/api/sg_150/image/{entry_id}/{NEWEST['uid']}"


async def test_unexpected_image_list_is_a_readable_browse_error(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """A reply that is not {"images": [...]} names the problem."""
    with pytest.raises(BrowseError, match="Could not load the images of Kitchen"):
        await media_source.async_browse_media(
            hass, f"media-source://{DOMAIN}/{config_entry.entry_id}/pbx-internal-phone"
        )


async def test_image_resolves_to_proxy_view(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    hass_client: ClientSessionGenerator,
) -> None:
    """A resolved image is served by the authenticated proxy view."""
    entry_id = config_entry.entry_id
    resolved = await media_source.async_resolve_media(
        hass, f"media-source://{DOMAIN}/{entry_id}/pbx-external/{NEWEST['uid']}", None
    )
    assert resolved.mime_type == "image/jpeg"

    client = await hass_client()
    response = await client.get(resolved.url)

    assert response.status == 200
    assert response.content_type == "image/jpeg"
    assert await response.read() == JPEG


async def test_proxy_view_errors(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    hass_client: ClientSessionGenerator,
) -> None:
    """Unknown gateways are 404, images the gateway cannot serve are 502."""
    client = await hass_client()
    entry_id = config_entry.entry_id

    unknown_entry = await client.get(f"/api/sg_150/image/nope/{NEWEST['uid']}")
    missing_image = await client.get(f"/api/sg_150/image/{entry_id}/unknown-uid")
    empty_image = await client.get(f"/api/sg_150/image/{entry_id}/{OLDEST['uid']}")

    assert unknown_entry.status == 404
    assert missing_image.status == 502
    assert empty_image.status == 502
