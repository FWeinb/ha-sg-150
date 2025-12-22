"""Custom types for ha-sg-150."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.loader import Integration

    from sip.minisip import MiniSIPServer
    from .api import SG150ApiClient
    from .coordinator import SG150Coordinator


type SG150ConfigEntry = ConfigEntry[SG150RuntimeData]


@dataclass
class SG150RuntimeData:
    """Data for the Blueprint integration."""

    server: MiniSIPServer
    client: SG150ApiClient
    coordinator: SG150Coordinator
    integration: Integration
