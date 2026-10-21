"""BlueprintEntity class."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import (
    EntityCategory,
)
from homeassistant.util.dt import as_local

from .entity import SG150GatewayEntity
from .line import Registered, Unregistered

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .line import GatewayLine, LineEvent


async def async_setup_entry(
    _: HomeAssistant,
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary platform."""
    entites = [
        SipRegistered(
            coordinator=entry.runtime_data.coordinator,
            line=entry.runtime_data.line,
        )
    ]
    async_add_entities(entites)


class SipRegistered(SG150GatewayEntity, BinarySensorEntity):
    """Binary Sensor Representing the SIP Connection Status."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    icon = "mdi:server-network-outline"

    def __init__(self, coordinator: SG150Coordinator, line: GatewayLine) -> None:
        """Create a new SipRegistered entity."""
        super().__init__(coordinator, key="sip_connection")
        self._line = line
        self._attr_extra_state_attributes = {"user": line.user}

        self.update_state()

    async def async_added_to_hass(self) -> None:
        """Subscribe to line events."""
        self.async_on_remove(self._line.subscribe(self._on_line_event))

    def _on_line_event(self, event: LineEvent) -> None:
        """Update when the registration changes."""
        if isinstance(event, (Registered, Unregistered)):
            self.update_state()
            self.async_write_ha_state()

    def update_state(self) -> None:
        """Update the boolean state of the binary entity."""
        registration = self._line.registration
        self._attr_is_on = registration is not None
        if registration is not None:
            addr = registration.addr
            expires_at = as_local(
                datetime.fromtimestamp(registration.expires_at, tz=UTC)
            )

            self._attr_extra_state_attributes.update(
                {
                    "sip-client": f"{addr[0]}:{addr[1]}",
                    "expires-at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
