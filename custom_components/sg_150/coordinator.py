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

from .api import SG150ApiClient, SG150ApiClientAuthenticationError, SG150ApiClientError
from .const import DOMAIN, LOGGER, MANUFACTURER

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .data import SG150ConfigEntry
    from .types import SG150Device, SG150MaschineInfo


@dataclass
class SG150Data:
    """Data retrived from the SG150 Gateway."""

    devices: list[SG150Device]

    def by_id(self, _id: str) -> SG150Device | None:
        """Get device by id, or None if the gateway no longer reports it."""
        return next((device for device in self.devices if device.id == _id), None)


class SG150Coordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    config_entry: SG150ConfigEntry
    machine_info: SG150MaschineInfo | None = None
    gateway_device_id: str | None = None

    data: SG150Data

    def __init__(self, hass: HomeAssistant, config_entry: SG150ConfigEntry) -> None:
        """Initialize coordinator."""
        super().__init__(
            hass=hass,
            logger=LOGGER,
            name=DOMAIN,
            config_entry=config_entry,
            update_interval=timedelta(seconds=30),
        )

    def get_gateway_identifier(self) -> tuple[str, str]:
        """Get the identifier of the gateway device in the device registry."""
        return (self.config_entry.domain, self.config_entry.entry_id)

    async def async_register_gateway_device(self) -> None:
        """Register the gateway so device entities can link to it via its id."""
        machine_info = self.machine_info
        self.gateway_device_id = (
            dr.async_get(self.hass)
            .async_get_or_create(
                config_entry_id=self.config_entry.entry_id,
                identifiers={self.get_gateway_identifier()},
                name="Smart Gateway 150",
                manufacturer=MANUFACTURER,
                model=machine_info.machineName or "Unknown",
                hw_version=machine_info.machineRevision or "?",
                serial_number=machine_info.macAddress or "?",
            )
            .id
        )

    def get_api_client(self) -> SG150ApiClient:
        """Get the API client."""
        return self.config_entry.runtime_data.client

    async def _async_setup(self) -> None:
        """Set up coordinator."""
        try:
            self.machine_info = await self.get_api_client().async_get_machine_info()
        except SG150ApiClientAuthenticationError as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except SG150ApiClientError as exception:
            raise UpdateFailed(exception) from exception

    async def _async_update_data(self) -> Any:
        """Update data via library."""
        try:
            data = await self.get_api_client().async_get_in_home_callable()
        except SG150ApiClientAuthenticationError as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except SG150ApiClientError as exception:
            raise UpdateFailed(exception) from exception

        # An empty reply may be transient; it must not wipe every device.
        if data.devices:
            self._remove_stale_devices({device.id for device in data.devices})
        return SG150Data(data.devices)

    def _remove_stale_devices(self, current: set[str]) -> None:
        """
        Detach registry devices the gateway no longer reports.

        The registry is compared rather than the previous reply, so devices
        removed while Home Assistant was not running are detached as well.
        """
        device_registry = dr.async_get(self.hass)
        gateway = self.get_gateway_identifier()
        for device in dr.async_entries_for_config_entry(
            device_registry, self.config_entry.entry_id
        ):
            ids = {
                identifier
                for domain, identifier in device.identifiers
                if domain == DOMAIN and (domain, identifier) != gateway
            }
            if ids and not ids & current:
                LOGGER.info("Removing device %s, the gateway removed it", device.name)
                device_registry.async_update_device(
                    device_id=device.id,
                    remove_config_entry_id=self.config_entry.entry_id,
                )
