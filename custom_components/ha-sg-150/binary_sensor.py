
"""BlueprintEntity class."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import (
    EntityCategory,
)

from .const import CONF_SIP_USER
from .entity import SG150PushEntity
from .coordinator import SG150Coordinator

if TYPE_CHECKING:
    from .sip.minisip import MiniSIPServer


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001 Unused function argument: `hass`
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary platform."""
    entites = [
        SipRegistered(
            coordinator=entry.runtime_data.coordinator,
            user=entry.options.get(CONF_SIP_USER),
            minisip=entry.runtime_data.server
        )
    ]
    async_add_entities(entites)


class SipRegistered(SG150PushEntity, BinarySensorEntity):
    def __init__(self, coordinator: SG150Coordinator, user: str, minisip: MiniSIPServer) -> None:
        super().__init__(coordinator)
        self._user = user
        self._minisip = minisip

        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_translation_key = "sip_connection"
        self._attr_name = coordinator.get_enity_name(
            "HomeAssistant SIP Connection")
        self._attr_extra_state_attributes = {"user": user}
        self.icon = "mdi:server-network-outline"

        self.update_state()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._minisip.add_listener("on_register", self.async_update_state)
        )

    async def async_update_state(self, username: str, addr: (str, int)):
        self.update_state()
        self.schedule_update_ha_state()

    def update_state(self):
        addr = self._minisip.registrations.get(self._user, None)
        self._attr_is_on = True if addr != None else False
        if self._attr_is_on:
            self._attr_extra_state_attributes["sip-client"] = f"{addr[0]}:{addr[1]}"
