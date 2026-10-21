"""Shared test objects."""

import json
from pathlib import Path

from custom_components.sg_150.types import SG150Device, SG150Devices

FIXTURES = Path(__file__).parent / "fixtures"


def load_devices() -> dict[str, SG150Device]:
    """Load the system/devices fixture keyed by device id."""
    payload = json.loads((FIXTURES / "system_devices.json").read_text())
    return {device.id: device for device in SG150Devices(**payload).devices}


class FakeTransport:
    """Simple transport stub capturing outbound datagrams."""

    def __init__(self) -> None:
        """Create a new Fake Transport."""
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        """Record the data and address."""
        self.sent.append((data, addr))
