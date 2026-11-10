"""Button entites for the SG-150."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from homeassistant.components.button import ButtonEntity
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from .api import SG150ApiClientError
from .const import DOMAIN
from .entity import (
    SG150DeviceEntity,
    SG150GatewayEntity,
    async_add_device_entities,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.entity_platform import AddEntitiesCallback

    from .coordinator import SG150Coordinator
    from .data import SG150ConfigEntry
    from .line import GatewayLine
    from .types import SG150Device


async def async_setup_entry(
    _: HomeAssistant,
    entry: SG150ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the button platform."""
    coordinator = entry.runtime_data.coordinator
    async_add_entities([LightSwitchButton(coordinator=coordinator)])

    def create(device: SG150Device) -> list[ButtonEntity]:
        buttons: list[ButtonEntity] = []
        if device.is_door:
            buttons.append(DoorOpenerButton(coordinator=coordinator, device=device))
        # Next to the camera, whose live view talks on the same calls.
        if device.mjpeg_stream_url is not None:
            buttons.append(
                HangUpButton(
                    coordinator=coordinator, device=device, line=entry.runtime_data.line
                )
            )
        return buttons

    async_add_device_entities(entry, async_add_entities, create)


async def _gateway_request(request: Awaitable[None]) -> None:
    """Await a gateway request, turning its errors into HomeAssistantError."""
    try:
        await request
    except SG150ApiClientError as err:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="gateway_request_failed",
            translation_placeholders={"error": str(err)},
        ) from err


class DoorOpenerButton(SG150DeviceEntity, ButtonEntity):
    """Button Entity triggering the door opener when pressed."""

    icon = "mdi:door-open"

    def __init__(self, coordinator: SG150Coordinator, device: SG150Device) -> None:
        """Initialize the door opener button."""
        super().__init__(coordinator, device, key="door_opener")

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Handle the button press."""
        device = self.get_device()
        if device is None or device.phone_endpoint is None:
            return
        await _gateway_request(
            self.coordinator.get_api_client().async_trigger_door_opener(
                device.phone_endpoint.callNumber.dialable
            )
        )


class HangUpButton(SG150DeviceEntity, ButtonEntity):
    """Button Entity ending the calls of a camera's device when pressed."""

    icon = "mdi:phone-hangup"

    def __init__(
        self, coordinator: SG150Coordinator, device: SG150Device, line: GatewayLine
    ) -> None:
        """Initialize the hang up button."""
        super().__init__(coordinator, device, key="hang_up")
        self._line = line

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Hang up every call this device is on, or refuse if there is none."""
        calls = [c for c in self._line.calls.values() if c.involves(self._device_id)]
        if not calls:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="no_call_to_hang_up"
            )
        for call in calls:
            with contextlib.suppress(ValueError):  # it ended meanwhile
                await call.hangup()


class LightSwitchButton(SG150GatewayEntity, ButtonEntity):
    """Button Entity triggering the light switch when pressed."""

    icon = "mdi:lightbulb-on-outline"

    def __init__(self, coordinator: SG150Coordinator) -> None:
        """Initialize the light switch button."""
        super().__init__(coordinator, key="light_switch")

    def press(self) -> None:
        """Do not support the synchronous button API."""
        raise NotImplementedError

    async def async_press(self) -> None:
        """Handle the button press."""
        await _gateway_request(
            self.coordinator.get_api_client().async_trigger_light_switch()
        )
