"""Base entity classes for the SG-150."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import MANUFACTURER
from .coordinator import SG150Coordinator

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from homeassistant.helpers.entity import Entity
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .data import SG150ConfigEntry
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
        self._attr_translation_key = key
        self._attr_unique_id = gateway_unique_id(
            coordinator.machine_info.macAddress, key
        )
        self._attr_device_info = DeviceInfo(
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
            via_device_id=coordinator.gateway_device_id,
        )

    def get_device(self) -> SG150Device | None:
        """Get the device's data, or None if the gateway no longer reports it."""
        return self.coordinator.data.by_id(self._device_id)

    @property
    def available(self) -> bool:
        """Return whether the gateway is reachable and still reports the device."""
        return super().available and self.get_device() is not None


@callback
def async_add_device_entities(
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
    create: Callable[[SG150Device], Iterable[Entity]],
) -> None:
    """Add the entities `create` returns for each device, also for new devices."""
    coordinator = entry.runtime_data.coordinator
    known: set[str] = set()

    @callback
    def add_new_devices() -> None:
        devices = coordinator.data.devices if coordinator.data else []
        new = [device for device in devices if device.id not in known]
        known.update(device.id for device in new)
        if entities := [entity for device in new for entity in create(device)]:
            async_add_entities(entities)

    add_new_devices()
    entry.async_on_unload(coordinator.async_add_listener(add_new_devices))
