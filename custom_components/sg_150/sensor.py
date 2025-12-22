"""BlueprintEntity class."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.sensor import SensorEntity
from homeassistant.const import (
    EntityCategory,
)

from .entity import SG150BaseDeviceEntity, SG150BaseEntity
from .helpers import (
    get_in_home_capability,
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
    """Set up the text platform."""
    entites = [MacAddressSensor(coordinator=entry.runtime_data.coordinator)]

    for device in entry.runtime_data.coordinator.data.devices:
        if is_door(device):
            entites.extend(
                [
                    DoorTypeSensor(
                        coordinator=entry.runtime_data.coordinator,
                        device=device,
                    )
                ]
            )
        if has_phone_endpoint(device):
            entites.extend(
                [
                    PhoneNumber(
                        coordinator=entry.runtime_data.coordinator,
                        device=device,
                    )
                ]
            )

    async_add_entities(entites)


class DoorTypeSensor(SG150BaseDeviceEntity, SensorEntity):
    """Sensor Entity representing the SG150 Door type."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "door_type"
    icon = "mdi:cellphone-cog"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the doorbell event entity."""
        super().__init__(coordinator, device, name="Door Type")

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        device = self.get_device()
        in_home_capability = get_in_home_capability(device)
        return in_home_capability.properties.deviceType


class PhoneNumber(SG150BaseDeviceEntity, SensorEntity):
    """Sensor Entity representing the SG150 phone number."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "phone_number"
    icon = "mdi:phone"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the doorbell event entity."""
        super().__init__(coordinator, device, name="Phone Number")

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        device = self.get_device()
        phone_capabilty = get_phone_endpoint_capability(device)
        call_number = phone_capabilty.properties.callNumber
        return f"{call_number.prefix} {call_number.extension}"


class MacAddressSensor(SG150BaseEntity, SensorEntity):
    """Sensor Entity representing the SG150 mac address."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_translation_key = "mac_address"
    _attr_name = "MAC Address"
    icon = "mdi:identifier"

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        return self.coordinator.machine_info.macAddress
