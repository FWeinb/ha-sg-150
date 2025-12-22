"""BlueprintEntity class."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.const import (
    EntityCategory,
)

from .const import MANUFACTURER
from .coordinator import SG150Coordinator
from .types import SG150Device


class SG150CoordinatorEntity(CoordinatorEntity[SG150Coordinator]):
    coordinator: SG150Coordinator

    def __init__(self, coordinator: SG150Coordinator) -> None:
        super().__init__(coordinator)


class SG150BaseEntity(SG150CoordinatorEntity):
    """BlueprintEntity class."""

    def __init__(self, coordinator: SG150Coordinator) -> None:
        super().__init__(coordinator)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_unique_id = coordinator.machine_info.macAddress
        self._attr_device_info = DeviceInfo(
            name="Smart Gateway 150",
            manufacturer=MANUFACTURER,
            model=coordinator.machine_info.machineName or "Unkown",
            hw_version=coordinator.machine_info.machineRevision or "?",
            serial_number=coordinator.machine_info.macAddress or "?",
            identifiers={coordinator.get_gateway_identifier()}
        )


class SG150PushEntity(SG150BaseEntity):
    def should_poll(self):
        return False


class SG150BaseDeviceEntity(SG150CoordinatorEntity):

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device, name: str) -> None:
        super().__init__(coordinator)
        self._device_id = device.id
        self._attr_unique_id = device.id + name
        self._attr_name = f"{coordinator.get_enity_name_for_device(device)} {name}"
        self._attr_device_info = DeviceInfo(
            identifiers={(coordinator.config_entry.domain, device.id)},
            name=device.name,
            manufacturer=MANUFACTURER,
            via_device=coordinator.get_gateway_identifier()
        )

    def get_device(self) -> SG150Device:
        return self.coordinator.data.by_id(self._device_id)


class SG150PushDeviceEntity(SG150BaseDeviceEntity):
    def should_poll(self):
        return False
