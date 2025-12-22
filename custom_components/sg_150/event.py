"""Component providing support for doorbell events."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from homeassistant.components.event import EventDeviceClass, EventEntity

from .const import LOGGER
from .entity import SG150PushDeviceEntity
from .helpers import get_phone_endpoint_capability, is_external_pbx_phone

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .sip.minisip import CallContext, MiniSIPServer
    from .types import SG150Device


async def async_setup_entry(
    _: HomeAssistant,
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary_sensor platform."""
    if entry.runtime_data.coordinator.data is None:
        LOGGER.warning("Coordinator data is None, skipping binary_sensor setup")
        return

    async_add_entities(
        [
            SG150RingingEvent(
                coordinator=entry.runtime_data.coordinator,
                device=device,
                minisip=entry.runtime_data.server,
            )
            for device in entry.runtime_data.coordinator.data.devices
            if is_external_pbx_phone(device)
        ]
    )


class SG150RingingEvent(SG150PushDeviceEntity, EventEntity):
    """Event Entity representing the SG150 ringing event."""

    _attr_device_class = EventDeviceClass.DOORBELL
    _attr_translation_key = "Bell"

    def __init__(
        self, coordinator: SG150Coordinator, device: SG150Device, minisip: MiniSIPServer
    ) -> None:
        """Initialize the doorbell event entity."""
        super().__init__(coordinator, device, name="Bell")
        self._attr_event_types = ["ringing"]
        self._minisip = minisip
        self.icon = "mdi:bell-ring"

        phone_endpoint = get_phone_endpoint_capability(device)
        self._phone_number = phone_endpoint.properties.callNumber

    async def async_update_state(self, call_context: CallContext) -> bool:
        """Update the ringing state based on the call_context."""
        LOGGER.info("Got called %s", call_context)

        self._trigger_event("ringing", dataclasses.asdict(call_context))
        self.schedule_update_ha_state()
        return True

    async def async_added_to_hass(self) -> None:
        """Register on_incoming_call callback with SipServer."""
        self.async_on_remove(
            self._minisip.add_listener("on_incoming_call", self.async_update_state)
        )
