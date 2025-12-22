from .types import SG150Device, SG150DeviceCapability, SG150DeviceCapabilityPhoneEndpoint, SG150DeviceCapabilityInHome, SG150DeviceCapabilityVideoExtraction


def is_door(device: SG150Device) -> bool:
    """Check if the capability indicates a door."""
    for capability in device.capabilities:
        if capability.type == "PHONE_ENDPOINT" and capability.properties.isDoor:
            return True
    return False


def is_external_pbx_phone(device: SG150Device) -> bool:
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
    for capability in device.capabilities:
        if capability.type == "VIDEO_SENDER":
            return True
    return False


def has_video_extraction(device: SG150Device) -> bool:
    """Check if the device has video capability."""
    for capability in device.capabilities:
        if capability.type == "VIDEO_EXTRACTION":
            return True
    return False


def get_video_extraction_capability(device: SG150Device) -> SG150DeviceCapabilityVideoExtraction:
    return get_capability(device, "VIDEO_EXTRACTION")


def get_phone_endpoint_capability(device: SG150Device) -> SG150DeviceCapabilityPhoneEndpoint:
    return get_capability(device, "PHONE_ENDPOINT")


def get_in_home_capability(device: SG150Device) -> SG150DeviceCapabilityInHome:
    return get_capability(device, "IN_HOME")


def get_capability(device: SG150Device, capabilites: str) -> SG150DeviceCapability:
    return next(capability for capability in device.capabilities if capability.type == capabilites)
