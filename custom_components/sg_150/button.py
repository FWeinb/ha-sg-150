"""Button entites for the SG-150."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.button import ButtonEntity

from .entity import SG150DeviceEntity, SG150GatewayEntity

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
            if device.is_door
        ]
    )


class DoorOpenerButton(SG150DeviceEntity, ButtonEntity):
    """Button Entity triggering the door opener when pressed."""

    icon = "mdi:door-open"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the door opener button."""
        super().__init__(coordinator, device, key="door_opener")

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Handle the button press."""
        phone_endpoint = self.get_device().phone_endpoint
        if phone_endpoint is None:
            return
        await self.coordinator.get_api_client().async_trigger_door_opener(
            phone_endpoint.callNumber.dialable
        )


class LightSwitchButton(SG150GatewayEntity, ButtonEntity):
    """Button Entity triggering the light switch when pressed."""

    icon = "mdi:lightbulb-on-outline"

    def __init__(self, coordinator: SG150Coordinator) -> None:
        """Initialize the light switch button."""
        super().__init__(coordinator, key="light_switch")

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Handle the button press."""
        await self.coordinator.get_api_client().async_trigger_light_switch()
