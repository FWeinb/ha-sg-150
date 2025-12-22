"""DataUpdateCoordinator for ha-sg-150."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import (
    device_registry as dr,
)
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    SG150ApiClientAuthenticationError,
    SG150ApiClientError,
)
from .const import DOMAIN, LOGGER

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import SG150ConfigEntry
    from .types import SG150Device, SG150MaschineInfo


@dataclass
class SG150Data:
    """Data retrived from the SG150 Gateway."""

    devices: list[SG150Device]

    def by_id(self, _id: str) -> SG150Device:
        """Get device by id."""
        LOGGER.debug("Get device by id %s", _id)
        return next(device for device in self.devices if device.id == _id)


class SG150Coordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    config_entry: SG150ConfigEntry
    machine_info: SG150MaschineInfo | None = None

    data: SG150Data

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize coordinator."""
        super().__init__(
            hass=hass,
            logger=LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),
        )
        self.previous_devices: set[str] = set()

    def get_gateway_identifier(self) -> tuple[str, str]:
        """Get the gateway identifier to be used within via_device."""
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
        self.machine_info = (
            await self.config_entry.runtime_data.client.async_get_machine_info()
        )

    async def _async_update_data(self) -> Any:
        """Update data via library."""
        try:
            data = (
                await self.config_entry.runtime_data.client.async_get_in_home_callable()
            )

            current_devices = {device.id for device in data.devices}
            if stale_devices := self.previous_devices - current_devices:
                device_registry = dr.async_get(self.hass)
                for device_id in stale_devices:
                    device = device_registry.async_get_device(
                        identifiers={(DOMAIN, device_id)}
                    )
                    if device:
                        device_registry.async_update_device(
                            device_id=device.id,
                            remove_config_entry_id=self.config_entry.entry_id,
                        )

            self.previous_devices = current_devices

            return SG150Data(data.devices)
        except SG150ApiClientAuthenticationError as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except SG150ApiClientError as exception:
            raise UpdateFailed(exception) from exception
