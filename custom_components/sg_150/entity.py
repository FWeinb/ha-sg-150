"""Base entity classes for the SG-150."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import MANUFACTURER
from .coordinator import SG150Coordinator

if TYPE_CHECKING:
    from .types import SG150Device

# Unique IDs of entities that existed before entity keys were introduced, kept so
# existing entities are not orphaned. Gateway entities used the bare MAC address
# (they are told apart by platform), device entities the device id plus a name.
_LEGACY_GATEWAY_KEYS = {"light_switch", "mac_address", "sip_connection"}
_LEGACY_DEVICE_SUFFIXES = {
    "bell": "Bell",
    "camera": "Camera",
    "door_opener": "Door Opener",
    "door_type": "Door Type",
    "phone_number": "Phone Number",
}


def gateway_unique_id(mac_address: str, key: str) -> str:
    """Return the unique id of a gateway entity."""
    return mac_address if key in _LEGACY_GATEWAY_KEYS else f"{mac_address}_{key}"


def device_unique_id(device_id: str, key: str) -> str:
    """Return the unique id of a device entity."""
    return device_id + _LEGACY_DEVICE_SUFFIXES.get(key, f"_{key}")


class SG150GatewayEntity(CoordinatorEntity[SG150Coordinator]):
    """An entity of the Smart Gateway itself, named by its translation key."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SG150Coordinator, key: str) -> None:
        """Create a gateway entity identified by `key`."""
        super().__init__(coordinator)
        machine_info = coordinator.machine_info
        self._attr_translation_key = key
        self._attr_unique_id = gateway_unique_id(machine_info.macAddress, key)
        self._attr_device_info = DeviceInfo(
            name="Smart Gateway 150",
            manufacturer=MANUFACTURER,
            model=machine_info.machineName or "Unknown",
            hw_version=machine_info.machineRevision or "?",
            serial_number=machine_info.macAddress or "?",
            identifiers={coordinator.get_gateway_identifier()},
        )


class SG150DeviceEntity(CoordinatorEntity[SG150Coordinator]):
    """An entity of a device behind the gateway, named by its translation key."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: SG150Coordinator, device: SG150Device, key: str
    ) -> None:
        """Create an entity of `device` identified by `key`."""
        super().__init__(coordinator)
        self._device_id = device.id
        self._attr_translation_key = key
        self._attr_unique_id = device_unique_id(device.id, key)
        self._attr_device_info = DeviceInfo(
            identifiers={(coordinator.config_entry.domain, device.id)},
            name=device.name,
            manufacturer=MANUFACTURER,
            via_device=coordinator.get_gateway_identifier(),
        )

    def get_device(self) -> SG150Device:
        """Get the device data associated with this entity."""
        return self.coordinator.data.by_id(self._device_id)
