"""Custom types for ha-sg-150."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from homeassistant.config_entries import ConfigEntry

if TYPE_CHECKING:
    from homeassistant.loader import Integration

    from .api import SG150ApiClient
    from .coordinator import SG150Coordinator
    from .line import GatewayLine


@dataclass
class SG150RuntimeData:
    """Runtime data of an SG-150 config entry."""

    line: GatewayLine
    client: SG150ApiClient
    coordinator: SG150Coordinator
    integration: Integration


type SG150ConfigEntry = ConfigEntry[SG150RuntimeData]
