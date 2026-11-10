"""Tests for the typed device capability accessors."""

import unittest

from custom_components.sg_150.types import (
    SG150DeviceCallNumber,
    SG150DeviceCapabilityUnknown,
    SG150DeviceType,
)
from tests.utils import load_devices


class DeviceCapabilityTests(unittest.TestCase):
    """Capability accessors on SG150Device."""

    def setUp(self) -> None:
        """Parse the fixture."""
        self.devices = load_devices()

    def test_door_station_capabilities(self) -> None:
        """A door station exposes its phone endpoint, video and in-home data."""
        door = self.devices["door-front"]

        assert door.is_door
        assert not door.is_external_pbx_phone
        assert door.phone_endpoint is not None
        assert door.phone_endpoint.callNumber.dialable == "*111"
        assert door.video_extraction is not None
        assert door.video_extraction.type == "MJPEG_STREAM"
        assert door.video_extraction.url == "http://192.0.2.10/video/door-front.mjpeg"
        assert door.in_home is not None
        assert door.in_home.deviceType == "SMART_DOOR_STATION"

    def test_device_without_capabilities_returns_none(self) -> None:
        """Missing capabilities are reported as None, not raised."""
        indoor = self.devices["indoor-hall"]

        assert indoor.phone_endpoint is None
        assert indoor.video_extraction is None
        assert not indoor.is_door
        assert not indoor.is_external_pbx_phone

        app = self.devices["app-phone"]
        assert app.in_home is None
        assert app.phone_endpoint is None

    def test_external_pbx_phone(self) -> None:
        """Only PBX phones on an EXTERNAL PBX system count as external."""
        assert self.devices["pbx-external"].is_external_pbx_phone
        assert not self.devices["pbx-external"].is_door
        assert not self.devices["pbx-internal-phone"].is_external_pbx_phone

    def test_external_pbx_requires_pbxphone_device_type(self) -> None:
        """An EXTERNAL pbx system on a non-PBXPHONE device is not a PBX phone."""
        door = self.devices["door-front"].model_copy(deep=True)
        door.phone_endpoint.pbxSystem.type = "EXTERNAL"

        assert not door.is_external_pbx_phone

    def test_unknown_values_from_new_firmware_still_load(self) -> None:
        """Unknown capability, device and video types do not fail validation."""
        door = self.devices["door-front"]
        unknown = [
            capability.root
            for capability in door.capabilities
            if isinstance(capability.root, SG150DeviceCapabilityUnknown)
        ]
        assert [capability.type for capability in unknown] == ["DOOR_LIGHT"]
        assert door.phone_endpoint is not None

        intercom = self.devices["intercom-new"]
        assert intercom.type == "VIDEO_INTERCOM"
        assert intercom.in_home is not None
        assert intercom.in_home.deviceType == "VIDEO_INTERCOM"
        assert intercom.video_extraction is not None
        assert intercom.mjpeg_stream_url is None
        assert not intercom.is_door
        assert not intercom.is_external_pbx_phone

    def test_known_device_type_is_the_enum(self) -> None:
        """Known device types still parse to SG150DeviceType."""
        assert self.devices["pbx-external"].type is SG150DeviceType.PBXPHONE


class CallNumberTests(unittest.TestCase):
    """Formatting of SG150DeviceCallNumber."""

    def test_dialable_concatenates_prefix_and_extension(self) -> None:
        """The dial string has no separator."""
        number = SG150DeviceCallNumber(prefix="*1", extension="11")

        assert number.dialable == "*111"
        assert number.display == "*1 11"

    def test_missing_prefix_is_omitted(self) -> None:
        """A missing prefix must not render as 'None'."""
        number = SG150DeviceCallNumber(prefix=None, extension="21")

        assert number.dialable == "21"
        assert number.display == "21"
