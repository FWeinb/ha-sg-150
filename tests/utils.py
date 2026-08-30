"""Shared test objects used in MiniSIP tests."""


class FakeTransport:
    """Simple transport stub capturing outbound datagrams."""

    def __init__(self) -> None:
        """Create a new Fake Transport."""
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        """Record the data and address."""
        self.sent.append((data, addr))
