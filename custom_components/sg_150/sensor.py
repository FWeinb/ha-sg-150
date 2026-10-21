"""Sensor entites for the SG-150."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.sensor import SensorEntity
from homeassistant.const import (
    EntityCategory,
)

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
    """Set up the sensor platform."""
    entites = [MacAddressSensor(coordinator=entry.runtime_data.coordinator)]

    for device in entry.runtime_data.coordinator.data.devices:
        if device.is_door:
            entites.extend(
                [
                    DoorTypeSensor(
                        coordinator=entry.runtime_data.coordinator,
                        device=device,
                    )
                ]
            )
        if device.phone_endpoint is not None:
            entites.extend(
                [
                    PhoneNumber(
                        coordinator=entry.runtime_data.coordinator,
                        device=device,
                    )
                ]
            )

    async_add_entities(entites)


class DoorTypeSensor(SG150DeviceEntity, SensorEntity):
    """Sensor Entity representing the SG150 Door type."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    icon = "mdi:cellphone-cog"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the door type sensor."""
        super().__init__(coordinator, device, key="door_type")

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        in_home = self.get_device().in_home
        return in_home.deviceType if in_home else None


class PhoneNumber(SG150DeviceEntity, SensorEntity):
    """Sensor Entity representing the SG150 phone number."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    icon = "mdi:phone"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the phone number sensor."""
        super().__init__(coordinator, device, key="phone_number")

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        phone_endpoint = self.get_device().phone_endpoint
        return phone_endpoint.callNumber.display if phone_endpoint else None


class MacAddressSensor(SG150GatewayEntity, SensorEntity):
    """Sensor Entity representing the SG150 mac address."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    icon = "mdi:identifier"

    def __init__(self, coordinator: SG150Coordinator) -> None:
        """Initialize the MAC address sensor."""
        super().__init__(coordinator, key="mac_address")

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        return self.coordinator.machine_info.macAddress
