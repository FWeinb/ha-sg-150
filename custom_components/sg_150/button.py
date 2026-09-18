"""Button entites for the SG-150."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.button import ButtonEntity

from .entity import SG150BaseDeviceEntity, SG150BaseEntity
from .helpers import (
    get_phone_endpoint_capability,
    has_phone_endpoint,
    is_door,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .types import SG150Device


async def async_setup_entry(
    _: HomeAssistant,
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the button platform."""
    async_add_entities(
        [LightSwitchButton(coordinator=entry.runtime_data.coordinator)]
        + [
            DoorOpenerButton(
                coordinator=entry.runtime_data.coordinator,
                device=device,
            )
            for device in entry.runtime_data.coordinator.data.devices
            if is_door(device) and has_phone_endpoint(device)
        ]
    )


class DoorOpenerButton(SG150BaseDeviceEntity, ButtonEntity):
    """Button Entity triggering the door opener when pressed."""

    _attr_translation_key = "door_opener"
    icon = "mdi:door-open"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the door opener button."""
        super().__init__(coordinator, device, name="Door Opener")

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Handle the button press."""
        device = self.get_device()
        phone_capabilty = get_phone_endpoint_capability(device)
        call_number = phone_capabilty.properties.callNumber
        await self.coordinator.get_api_client().async_trigger_door_opener(
            f"{call_number.prefix}{call_number.extension}"
        )


class LightSwitchButton(SG150BaseEntity, ButtonEntity):
    """Button Entity triggering the light switch when pressed."""

    _attr_translation_key = "light_switch"
    icon = "mdi:lightbulb-on-outline"

    def __init__(self, coordinator: SG150Coordinator) -> None:
        """Initialize the light switch button."""
        super().__init__(coordinator)
        self._attr_entity_category = None

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Handle the button press."""
        await self.coordinator.get_api_client().async_trigger_light_switch()
