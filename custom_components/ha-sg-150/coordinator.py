"""DataUpdateCoordinator for ha-sg-150."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    SG150ApiClientAuthenticationError,
    SG150ApiClientError,
)

from .types import SG150MaschineInfo, SG150Device, SG150Devices
from .const import LOGGER

if TYPE_CHECKING:
    from .data import SG150ConfigEntry


@dataclass
class SG150Data():
    devices: list[SG150Device]

    def by_id(self, id: str) -> SG150Device:
        LOGGER.debug("Get device by id %s" % (id))
        return next(device for device in self.devices if device.id == id)


class SG150Coordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    config_entry: SG150ConfigEntry
    machine_info: SG150MaschineInfo | None = None

    data: SG150Data

    def get_gateway_identifier(self) -> tuple[str, str]:
        """Get the gateway identifier to be used within via_device"""
        if self.machine_info is None:
            return None
        return (self.config_entry.domain, self.config_entry.entry_id)

    def get_enity_name(self, value: str) -> str:
        """Get the entity name for a device."""
        return f"{self.machine_info.machineModel} {value}"

    def get_enity_name_for_device(self, device: SG150Device) -> str:
        """Get the entity name for a device."""
        return self.get_enity_name(device.name or device.id)

    async def _async_setup(self) -> None:
        """Set up coordinator."""
        self.machine_info = await self.config_entry.runtime_data.client.async_get_machine_info()

    async def _async_update_data(self) -> Any:
        """Update data via library."""
        try:
            data = await self.config_entry.runtime_data.client.async_get_in_home_callable()

            return SG150Data(data.devices)

        except SG150ApiClientAuthenticationError as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except SG150ApiClientError as exception:
            raise UpdateFailed(exception) from exception
