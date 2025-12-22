"""Component providing support for doorbell events."""

from __future__ import annotations

import json

from typing import TYPE_CHECKING

from homeassistant.core import HomeAssistant, callback
from homeassistant.components.event import EventDeviceClass, EventEntity
from homeassistant.helpers.device_registry import DeviceInfo

from .entity import SG150PushDeviceEntity
from .const import LOGGER
from .helpers import is_external_pbx_phone, get_phone_endpoint_capability
from .types import SG150Device, SG150DeviceCallNumber

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from .data import SG150ConfigEntry
    from .sip.minisip import MiniSIPServer, CallContext


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001 Unused function argument: `hass`
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary_sensor platform."""
    if entry.runtime_data.coordinator.data is None:
        LOGGER.warn("Coordinator data is None, skipping binary_sensor setup")
        return

    entites = []

    for device in entry.runtime_data.coordinator.data.devices:
        if (is_external_pbx_phone(device)):
            entites.append(
                SG150RingingEvent(
                    coordinator=entry.runtime_data.coordinator,
                    device=device,
                    minisip=entry.runtime_data.server
                )
            )

    async_add_entities(entites)


class SG150RingingEvent(SG150PushDeviceEntity, EventEntity):

    _attr_device_class = EventDeviceClass.DOORBELL
    _attr_event_types = ["RINGING"]

    def __init__(
        self,
        coordinator: SG150Coordinator,
        device: SG150Device,
        minisip: MiniSIPServer
    ) -> None:
        """Initialize the doorbell event entity."""
        super().__init__(coordinator, device, name="Bell")
        self._minisip = minisip
        self.icon = "mdi:bell-ring"

        phone_endpoint = get_phone_endpoint_capability(device)
        self._phone_number = phone_endpoint.properties.callNumber

    async def async_update_state(self, call_context: CallContext) -> bool:
        LOGGER.info("Got called %s", call_context)

        self._trigger_event("RINGING", call_context)
        self.schedule_update_ha_state()
        return True

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._minisip.add_listener(
                "on_incoming_call", self.async_update_state)
        )
