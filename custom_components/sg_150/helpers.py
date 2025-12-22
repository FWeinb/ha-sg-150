"""Various helper methods."""

from .types import (
    SG150Device,
    SG150DeviceCapability,
    SG150DeviceCapabilityInHome,
    SG150DeviceCapabilityPhoneEndpoint,
    SG150DeviceCapabilityVideoExtraction,
)


def is_door(device: SG150Device) -> bool:
    """Check if the capability indicates a door."""
    for capability in device.capabilities:
        if capability.type == "PHONE_ENDPOINT" and capability.properties.isDoor:
            return True
    return False


def is_external_pbx_phone(device: SG150Device) -> bool:
    """Check if the capability indicates a external pbx phone system."""
    if device.type == "PBXPHONE":
        for capability in device.capabilities:
            if capability.type == "PHONE_ENDPOINT":
                return capability.properties.pbxSystem.type == "EXTERNAL"

    return False


def has_phone_endpoint(device: SG150Device) -> bool:
    """Check if the capability indicates a app."""
    for capability in device.capabilities:
        if capability.type == "PHONE_ENDPOINT":
            return True
    return False


def has_video_sender(device: SG150Device) -> bool:
    """Check if the device has video capability."""
    return any(capability.type == "VIDEO_SENDER" for capability in device.capabilities)


def has_video_extraction(device: SG150Device) -> bool:
    """Check if the device has video capability."""
    for capability in device.capabilities:
        if capability.type == "VIDEO_EXTRACTION":
            return True
    return False


def get_video_extraction_capability(
    device: SG150Device,
) -> SG150DeviceCapabilityVideoExtraction:
    """Get the VIDEO_EXTRACTION capability."""
    return get_capability(device, "VIDEO_EXTRACTION")


def get_phone_endpoint_capability(
    device: SG150Device,
) -> SG150DeviceCapabilityPhoneEndpoint:
    """Get the PHONE_ENDPOINT capability."""
    return get_capability(device, "PHONE_ENDPOINT")


def get_in_home_capability(device: SG150Device) -> SG150DeviceCapabilityInHome:
    """Get the IN_HOME capability."""
    return get_capability(device, "IN_HOME")


def get_capability(device: SG150Device, capability_type: str) -> SG150DeviceCapability:
    """Get a specific capability from the device."""
    return next(
        capability
        for capability in device.capabilities
        if capability.type == capability_type
    )
