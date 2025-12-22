"""BlueprintEntity class."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import (
    EntityCategory,
)
from homeassistant.util.dt import as_local

from .const import CONF_SIP_USER
from .entity import SG150PushEntity

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .sip.minisip import MiniSIPServer


async def async_setup_entry(
    _: HomeAssistant,
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary platform."""
    entites = [
        SipRegistered(
            coordinator=entry.runtime_data.coordinator,
            user=entry.options.get(CONF_SIP_USER),
            minisip=entry.runtime_data.server,
        )
    ]
    async_add_entities(entites)


class SipRegistered(SG150PushEntity, BinarySensorEntity):
    """Binary Sensor Representing the SIP Connection Status."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "sip_connection"
    icon = "mdi:server-network-outline"

    def __init__(
        self, coordinator: SG150Coordinator, user: str, minisip: MiniSIPServer
    ) -> None:
        """Create a new SipRegistered entity."""
        super().__init__(coordinator)
        self._user = user
        self._minisip = minisip
        self._attr_extra_state_attributes = {"user": user}

        self.update_state()

    async def async_added_to_hass(self) -> None:
        """Subscribe to on_register events."""
        self.async_on_remove(
            self._minisip.add_listener("on_register", self.async_update_state)
        )

    async def async_update_state(self, _: str, __: (str, int)) -> None:
        """on_register callback."""
        self.update_state()
        self.schedule_update_ha_state()

    def update_state(self) -> None:
        """Update the boolean state of the binary entity."""
        registration = self._minisip.registrations.get(self._user, None)
        addr = registration["addr"] if registration is not None else None
        self._attr_is_on = addr is not None
        if self._attr_is_on:
            expires_at = as_local(
                datetime.fromtimestamp(registration["expires_at"], tz=UTC)
            )

            self._attr_extra_state_attributes.update(
                {
                    "sip-client": f"{addr[0]}:{addr[1]}",
                    "expires-at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
