"""BlueprintEntity class."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.components.sensor import SensorEntity
from homeassistant.const import (
    EntityCategory,
)

from .const import LOGGER
from .types import SG150Device
from .helpers import is_door, has_phone_endpoint, get_phone_endpoint_capability, get_in_home_capability
from .entity import SG150BaseEntity, SG150BaseDeviceEntity
from .coordinator import SG150Coordinator


async def async_setup_entry(
    hass: HomeAssistant,  # noqa: ARG001 Unused function argument: `hass`
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the text platform."""
    entites = [
        MacAddressSensor(
            coordinator=entry.runtime_data.coordinator
        )
    ]

    for device in entry.runtime_data.coordinator.data.devices:
        if (is_door(device)):
            entites.extend([
                DoorTypeSensor(
                    coordinator=entry.runtime_data.coordinator,
                    device=device,
                )
            ])
        if (has_phone_endpoint(device)):
            entites.extend([
                PhoneNumber(
                    coordinator=entry.runtime_data.coordinator,
                    device=device,
                )
            ])

    async_add_entities(entites)


class DoorTypeSensor(SG150BaseDeviceEntity, SensorEntity):
    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        super().__init__(coordinator, device, name="Door Type")
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_translation_key = "door_type"
        self.icon = "mdi:cellphone-cog"

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        device = self.get_device()
        in_home_capability = get_in_home_capability(device)
        return in_home_capability.properties.deviceType


class DoorTypeSensor(SG150BaseDeviceEntity, SensorEntity):
    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        super().__init__(coordinator, device, name="Door Type")
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_translation_key = "door_type"
        self.icon = "mdi:cellphone-cog"

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        device = self.get_device()
        in_home_capability = get_in_home_capability(device)
        return in_home_capability.properties.deviceType


class PhoneNumber(SG150BaseDeviceEntity, SensorEntity):
    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        super().__init__(coordinator, device, name="Phone Number")
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_translation_key = "phone_number"
        self.icon = "mdi:phone"

    @property
    def native_value(self) -> str | None:
        """Return the native value of the sensor."""
        device = self.get_device()
        phone_capabilty = get_phone_endpoint_capability(device)
        callNumber = phone_capabilty.properties.callNumber
        return "%s %s" % (callNumber.prefix, callNumber.extension)


class MacAddressSensor(SG150BaseEntity, SensorEntity):
    def __init__(self, coordinator: SG150Coordinator) -> None:
        super().__init__(coordinator)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_translation_key = "mac_address"
        self._attr_name = coordinator.get_enity_name("MAC Address")
        self.icon = "mdi:identifier"

    @property
    def native_value(self) -> str | None:
        return self.coordinator.machine_info.macAddress


class MacAddressSensor(SG150BaseEntity, SensorEntity):
    def __init__(self, coordinator: SG150Coordinator) -> None:
        super().__init__(coordinator)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_translation_key = "mac_address"
        self._attr_name = coordinator.get_enity_name("MAC Address")
        self.icon = "mdi:identifier"

    @property
    def native_value(self) -> str | None:
        return self.coordinator.machine_info.macAddress
