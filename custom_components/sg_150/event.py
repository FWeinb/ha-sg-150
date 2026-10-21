"""Component providing support for doorbell events."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.event import (
    DoorbellEventType,
    EventDeviceClass,
    EventEntity,
)

from .const import LOGGER
from .entity import SG150PushDeviceEntity
from .line import IncomingCall

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .line import GatewayLine, LineEvent
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
                line=entry.runtime_data.line,
            )
            for device in entry.runtime_data.coordinator.data.devices
            if device.is_external_pbx_phone
        ]
    )


class SG150RingingEvent(SG150PushDeviceEntity, EventEntity):
    """Event Entity representing the SG150 ringing event."""

    _attr_device_class = EventDeviceClass.DOORBELL
    _attr_translation_key = "Bell"

    def __init__(
        self,
        coordinator: SG150Coordinator,
        device: SG150Device,
        line: GatewayLine,
    ) -> None:
        """Initialize the doorbell event entity."""
        super().__init__(coordinator, device, name="Bell")
        self._attr_event_types = [DoorbellEventType.RING, "ringing"]
        self._line = line
        self.icon = "mdi:bell-ring"

    def _on_line_event(self, event: LineEvent) -> None:
        """Ring when this device is being called."""
        if not isinstance(event, IncomingCall) or event.call.callee is None:
            return
        if event.call.callee.id != self._device_id:
            return

        call = event.call
        LOGGER.info("Got called %s", call)
        self._trigger_event(
            "ringing",
            {
                "call_id": call.id,
                "called_from": call.from_header,
                "called_to": call.to_header,
                "addr": call.addr,
            },
        )
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Subscribe to line events."""
        self.async_on_remove(self._line.subscribe(self._on_line_event))
