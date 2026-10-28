"""Two-way audio as Home Assistant sees it: options, camera and call model."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeassistant.components.labs import async_update_preview_feature
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
from pytest_homeassistant.common import MockConfigEntry

from custom_components.sg_150.const import (
    CONF_SIP_AUTO_ANSWER,
    CONF_TWO_WAY_AUDIO,
    DOMAIN,
)
from tests.sip_messages import GATEWAY, HA_NUMBER, cancel, invite

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant.typing import WebSocketGenerator

    from custom_components.sg_150.sip.minisip import MiniSIPServer


@pytest.fixture
def config_entry(config_entry: MockConfigEntry) -> MockConfigEntry:
    """Return the gateway entry with two-way audio on and auto answer off."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=config_entry.title,
        unique_id=config_entry.unique_id,
        data=config_entry.data,
        options={
            **config_entry.options,
            CONF_SIP_AUTO_ANSWER: False,
            CONF_TWO_WAY_AUDIO: True,
        },
    )


async def _capabilities(hass: HomeAssistant, ws: WebSocketGenerator) -> dict:
    camera = er.async_get(hass).async_get_entity_id(
        "camera", DOMAIN, "door-frontCamera"
    )
    client = await ws()
    await client.send_json_auto_id({"type": "camera/capabilities", "entity_id": camera})
    response = await client.receive_json()
    assert response["success"], response
    return response["result"]


@pytest.mark.usefixtures("setup_integration")
async def test_camera_offers_webrtc_and_talk_with_the_labs_feature(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """The live view is WebRTC; the talk button needs the Labs feature too."""
    assert await _capabilities(hass, hass_ws_client) == {
        "frontend_stream_types": ["web_rtc"],
        "two_way_audio": False,
    }

    assert await async_setup_component(hass, "labs", {})
    await async_update_preview_feature(hass, "camera", "two_way_audio", enabled=True)

    assert (await _capabilities(hass, hass_ws_client))["two_way_audio"] is True


async def test_incoming_call_rings_along_until_cancelled(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """Without auto answer, the call rings instead of being rejected busy."""
    await setup_integration.handle_datagram(invite("c1", "*111", HA_NUMBER), GATEWAY)
    await hass.async_block_till_done()

    statuses = [d.split(b"\r\n", 1)[0] for d, _ in setup_integration.transport.sent]
    assert statuses == [b"SIP/2.0 180 Ringing"]
    assert "c1" in setup_integration.ringing

    await setup_integration.handle_datagram(cancel("c1"), GATEWAY)

    assert not setup_integration.ringing
