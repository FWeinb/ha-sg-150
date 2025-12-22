"""BlueprintEntity class."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.const import (
    EntityCategory,
)
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import MANUFACTURER
from .coordinator import SG150Coordinator

if TYPE_CHECKING:
    from .types import SG150Device


class SG150CoordinatorEntity(CoordinatorEntity[SG150Coordinator]):
    """SG150 Coordinator entity definition."""

    coordinator: SG150Coordinator

    def __init__(self, coordinator: SG150Coordinator) -> None:
        """Create a new instance."""
        super().__init__(coordinator)


class SG150BaseEntity(SG150CoordinatorEntity):
    """BlueprintEntity class."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SG150Coordinator) -> None:
        """Create a new instance."""
        super().__init__(coordinator)
        self._attr_entity_category = EntityCategory.DIAGNOSTIC
        self._attr_unique_id = coordinator.machine_info.macAddress
        self._attr_device_info = DeviceInfo(
            name="Smart Gateway 150",
            manufacturer=MANUFACTURER,
            model=coordinator.machine_info.machineName or "Unkown",
            hw_version=coordinator.machine_info.machineRevision or "?",
            serial_number=coordinator.machine_info.macAddress or "?",
            identifiers={coordinator.get_gateway_identifier()},
        )


class SG150PushEntity(SG150BaseEntity):
    """Base Entity class that is not using polling."""

    should_poll = False


class SG150BaseDeviceEntity(SG150CoordinatorEntity):
    """Base device based entity."""

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: SG150Coordinator, device: SG150Device, name: str
    ) -> None:
        """Create a new instance."""
        super().__init__(coordinator)
        self._device_id = device.id
        self._attr_unique_id = device.id + name
        self._attr_name = name
        self._attr_device_info = DeviceInfo(
            identifiers={(coordinator.config_entry.domain, device.id)},
            name=device.name,
            manufacturer=MANUFACTURER,
            via_device=coordinator.get_gateway_identifier(),
        )

    def get_device(self) -> SG150Device:
        """Get the device data associated with this entity."""
        return self.coordinator.data.by_id(self._device_id)


class SG150PushDeviceEntity(SG150BaseDeviceEntity):
    """Base Device Entity class that is not using polling."""

    should_poll = False
