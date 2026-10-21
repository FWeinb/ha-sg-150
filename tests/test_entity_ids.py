"""Entity identity must stay stable across refactors."""

import unittest
from unittest.mock import MagicMock

from custom_components.sg_150.binary_sensor import SipRegistered
from custom_components.sg_150.button import DoorOpenerButton, LightSwitchButton
from custom_components.sg_150.camera import SG150Camera
from custom_components.sg_150.event import SG150RingingEvent
from custom_components.sg_150.sensor import (
    DoorTypeSensor,
    MacAddressSensor,
    PhoneNumber,
)
from custom_components.sg_150.types import SG150MaschineInfo
from tests.utils import load_devices

MAC = "00:11:22:33:44:55"


def make_coordinator() -> MagicMock:
    """Return a coordinator stub with machine info and a config entry."""
    coordinator = MagicMock()
    coordinator.machine_info = SG150MaschineInfo(
        machineModel="SG 150-0",
        machineName="Smart Gateway",
        machineRevision="1",
        productionBatch=1,
        macAddress=MAC,
    )
    coordinator.config_entry.domain = "sg_150"
    coordinator.config_entry.entry_id = "entry-1"
    coordinator.get_gateway_identifier.return_value = ("sg_150", "entry-1")
    return coordinator


class EntityIdentityTests(unittest.TestCase):
    """Unique ids are the ones used before entity keys were introduced."""

    def setUp(self) -> None:
        """Create a coordinator stub and load devices."""
        self.coordinator = make_coordinator()
        self.devices = load_devices()

    def test_gateway_entities_keep_legacy_unique_ids(self) -> None:
        """Gateway entities use the bare MAC address."""
        line = MagicMock(user="gateway", registration=None)
        entities = [
            LightSwitchButton(self.coordinator),
            MacAddressSensor(self.coordinator),
            SipRegistered(self.coordinator, line),
        ]

        assert [e.unique_id for e in entities] == [MAC, MAC, MAC]
        assert [e.translation_key for e in entities] == [
            "light_switch",
            "mac_address",
            "sip_connection",
        ]
        for entity in entities:
            assert entity.device_info["identifiers"] == {("sg_150", "entry-1")}
            assert entity.device_info["model"] == "Smart Gateway"

    def test_device_entities_keep_legacy_unique_ids(self) -> None:
        """Device entities use the device id plus their former name."""
        door = self.devices["door-front"]
        phone = self.devices["pbx-external"]
        line = MagicMock(calls={})
        entities = [
            ("door-front", "Door Opener", DoorOpenerButton(self.coordinator, door)),
            ("door-front", "Door Type", DoorTypeSensor(self.coordinator, door)),
            ("door-front", "Phone Number", PhoneNumber(self.coordinator, door)),
            ("door-front", "Camera", SG150Camera(self.coordinator, door, "x", line)),
            ("pbx-external", "Bell", SG150RingingEvent(self.coordinator, phone, line)),
        ]

        for device_id, legacy_name, entity in entities:
            assert entity.unique_id == device_id + legacy_name
            assert entity.device_info["identifiers"] == {("sg_150", device_id)}
            assert entity.device_info["via_device"] == ("sg_150", "entry-1")

    def test_device_entities_are_named_by_translation(self) -> None:
        """Names come from translations, not hard-coded English strings."""
        door = self.devices["door-front"]
        phone = self.devices["pbx-external"]
        line = MagicMock(calls={})

        assert DoorOpenerButton(self.coordinator, door).translation_key == (
            "door_opener"
        )
        assert SG150RingingEvent(self.coordinator, phone, line).translation_key == (
            "bell"
        )
        assert SG150Camera(
            self.coordinator, door, "http://x", line
        ).translation_key == ("camera")
