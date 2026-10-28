"""Entities of a set-up integration, driven through the gateway's API and SIP."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeassistant.const import STATE_OFF, STATE_ON, STATE_UNKNOWN
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import entity_registry as er

from custom_components.sg_150.const import DOMAIN
from tests.conftest import API_URL, MAC
from tests.sip_messages import GATEWAY, HA_NUMBER, ack, bye, invite, register

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant.test_util.aiohttp import (
        AiohttpClientMocker,
    )
    from pytest_homeassistant.typing import WebSocketGenerator

    from custom_components.sg_150.sip.minisip import MiniSIPServer

# (platform, unique id, friendly name). The unique ids are the ones used before
# entity keys existed and must not change, or existing entities are orphaned.
ENTITIES = [
    ("button", MAC, "Smart Gateway 150 Lightswitch"),
    ("sensor", MAC, "Smart Gateway 150 MAC Address"),
    ("binary_sensor", MAC, "Smart Gateway 150 HomeAssistant SIP Connection"),
    ("button", "door-frontDoor Opener", "Front Door Door Opener"),
    ("sensor", "door-frontDoor Type", "Front Door Door Type"),
    ("sensor", "door-frontPhone Number", "Front Door Phone Number"),
    ("camera", "door-frontCamera", "Front Door Camera"),
    ("button", "door-backDoor Opener", "Back Door Door Opener"),
    ("button", "door-front_hang_up", "Front Door Hang Up"),
    ("event", "pbx-externalBell", "Home Assistant Bell"),
    ("sensor", "pbx-externalPhone Number", "Home Assistant Phone Number"),
    ("sensor", "pbx-internal-phonePhone Number", "Kitchen Phone Phone Number"),
]


def entity_id(hass: HomeAssistant, platform: str, unique_id: str) -> str:
    """Look up an entity id by its unique id."""
    found = er.async_get(hass).async_get_entity_id(platform, DOMAIN, unique_id)
    assert found is not None, (platform, unique_id)
    return found


@pytest.mark.usefixtures("setup_integration")
@pytest.mark.parametrize(("platform", "unique_id", "name"), ENTITIES)
async def test_entities_keep_unique_ids_and_use_translated_names(
    hass: HomeAssistant, platform: str, unique_id: str, name: str
) -> None:
    """Each entity exists under its legacy unique id with a translated name."""
    state = hass.states.get(entity_id(hass, platform, unique_id))

    assert state is not None
    assert state.attributes["friendly_name"] == name


@pytest.mark.usefixtures("setup_integration")
async def test_sensors_show_gateway_data(hass: HomeAssistant) -> None:
    """Sensors report the MAC address, door type and display call numbers."""

    def state(unique_id: str) -> str:
        return hass.states.get(entity_id(hass, "sensor", unique_id)).state

    assert state(MAC) == MAC
    assert state("door-frontDoor Type") == "SMART_DOOR_STATION"
    assert state("door-frontPhone Number") == "*1 11"
    assert state("pbx-internal-phonePhone Number") == "21"


@pytest.mark.usefixtures("setup_integration")
async def test_door_opener_sends_dialable_call_number(
    hass: HomeAssistant, gateway_api: AiohttpClientMocker
) -> None:
    """Pressing the door opener posts the door's prefix and extension."""
    before = len(gateway_api.mock_calls)
    await hass.services.async_call(
        "button",
        "press",
        {"entity_id": entity_id(hass, "button", "door-frontDoor Opener")},
        blocking=True,
    )

    requests = [(str(url), body) for _, url, body, _ in gateway_api.mock_calls]
    assert requests[before:] == [
        (f"{API_URL}/in-home/openDoorRequests", {"callNumber": "*111"})
    ]


@pytest.mark.usefixtures("setup_integration")
async def test_hang_up_sits_next_to_each_camera(hass: HomeAssistant) -> None:
    """Hang Up is on the device with the camera, not on every door station."""
    registry = er.async_get(hass)
    camera = registry.async_get(entity_id(hass, "camera", "door-frontCamera"))
    hang_up = registry.async_get(entity_id(hass, "button", "door-front_hang_up"))

    assert hang_up.device_id == camera.device_id
    # The back door has a door opener, but only snapshots: no camera, no Hang Up.
    assert registry.async_get_entity_id("button", DOMAIN, "door-back_hang_up") is None


async def test_hang_up_ends_only_its_devices_calls(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """Pressing Hang Up sends BYE for calls with its device, and leaves others."""
    await setup_integration.handle_datagram(invite("c5", "*111", HA_NUMBER), GATEWAY)
    await setup_integration.handle_datagram(ack("c5"), GATEWAY)
    await setup_integration.handle_datagram(invite("c6", "*999", "*9999"), GATEWAY)
    await setup_integration.handle_datagram(ack("c6"), GATEWAY)

    await hass.services.async_call(
        "button",
        "press",
        {"entity_id": entity_id(hass, "button", "door-front_hang_up")},
        blocking=True,
    )

    assert list(setup_integration.active_calls) == ["c6"]
    assert setup_integration.transport.sent[-1][0].startswith(b"BYE ")


@pytest.mark.usefixtures("setup_integration")
async def test_hang_up_without_a_call_is_refused(hass: HomeAssistant) -> None:
    """Pressing Hang Up with no call shows an error instead of doing nothing."""
    with pytest.raises(ServiceValidationError) as err:
        await hass.services.async_call(
            "button",
            "press",
            {"entity_id": entity_id(hass, "button", "door-front_hang_up")},
            blocking=True,
        )

    assert err.value.translation_key == "no_call_to_hang_up"
    assert str(err.value) == "There is no call to hang up"


async def test_sip_connection_follows_registration(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """The connection sensor turns on when the gateway registers."""
    sensor = entity_id(hass, "binary_sensor", MAC)
    assert hass.states.get(sensor).state == STATE_OFF

    await register(setup_integration)
    await hass.async_block_till_done()

    state = hass.states.get(sensor)
    assert state.state == STATE_ON
    assert state.attributes["sip-client"] == f"{GATEWAY[0]}:{GATEWAY[1]}"


async def test_bell_rings_only_for_calls_to_its_phone(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """A call to the external phone rings its bell; unmatched calls do not."""
    bell = entity_id(hass, "event", "pbx-externalBell")

    await setup_integration.handle_datagram(invite("c1", "*999", "*9999"), GATEWAY)
    await hass.async_block_till_done()
    assert hass.states.get(bell).state == STATE_UNKNOWN

    await setup_integration.handle_datagram(invite("c2", "*111", HA_NUMBER), GATEWAY)
    await hass.async_block_till_done()

    state = hass.states.get(bell)
    assert state.state != STATE_UNKNOWN
    assert state.attributes["event_type"] == "ringing"
    assert state.attributes["call_id"] == "c2"


async def test_camera_streams_during_a_call_with_its_door(
    hass: HomeAssistant, setup_integration: MiniSIPServer
) -> None:
    """The door camera streams from the ACK of a call until its BYE."""
    camera = entity_id(hass, "camera", "door-frontCamera")
    assert hass.states.get(camera).state == "idle"

    await setup_integration.handle_datagram(invite("c3", "*111", HA_NUMBER), GATEWAY)
    await hass.async_block_till_done()
    assert hass.states.get(camera).state == "idle"

    await setup_integration.handle_datagram(ack("c3"), GATEWAY)
    await hass.async_block_till_done()
    assert hass.states.get(camera).state == "streaming"

    await setup_integration.handle_datagram(bye("c3"), GATEWAY)
    await hass.async_block_till_done()
    assert hass.states.get(camera).state == "idle"


async def test_camera_without_two_way_audio_stays_mjpeg(
    hass: HomeAssistant,
    setup_integration: MiniSIPServer,
    hass_ws_client: WebSocketGenerator,
) -> None:
    """With the option off, the camera offers no stream types (MJPEG only)."""
    client = await hass_ws_client()
    await client.send_json_auto_id(
        {
            "type": "camera/capabilities",
            "entity_id": entity_id(hass, "camera", "door-frontCamera"),
        }
    )
    response = await client.receive_json()

    assert response["result"] == {"frontend_stream_types": [], "two_way_audio": False}
