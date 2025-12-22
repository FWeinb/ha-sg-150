"""
Types used in the API.

These are used as return types of various API-Calls
"""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, RootModel


class SG150MaschineInfo(BaseModel):
    """API Maschine Info."""

    machineModel: str  # noqa: N815
    machineName: str  # noqa: N815
    machineRevision: str  # noqa: N815
    productionBatch: int  # noqa: N815
    macAddress: str  # noqa: N815


class SG150DeviceCallNumber(BaseModel):
    """API SG150DeviceCallNumber."""

    prefix: str | None
    extension: str | None


class SG150PbxSystem(BaseModel):
    """API SG150PbxSystem."""

    id: str
    name: str
    type: str
    externalExtension: SG150DeviceCallNumber  # noqa: N815


class SG150DeviceCapabilityPhoneEndpointProperties(BaseModel):
    """API SG150DeviceCapabilityPhoneEndpointProperties."""

    callNumber: SG150DeviceCallNumber  # noqa: N815
    isDoor: bool  # noqa: N815
    pbxSystem: SG150PbxSystem  # noqa: N815


class SG150DeviceCapabilityPhoneEndpoint(BaseModel):
    """API SG150DeviceCapabilityPhoneEndpoint."""

    type: Literal["PHONE_ENDPOINT"]
    properties: SG150DeviceCapabilityPhoneEndpointProperties


class SG150DeviceCapabilityCTIPhoneProperties(BaseModel):
    """API SG150DeviceCapabilityCTIPhoneProperties."""

    id: str | None
    name: str | None


class SG150DeviceCapabilityCTIPhone(BaseModel):
    """API SG150DeviceCapabilityCTIPhoneProperties."""

    type: Literal["CTI_PHONE"]
    properties: SG150DeviceCapabilityCTIPhoneProperties


class SG150DeviceCapabilityInHomeProperties(BaseModel):
    """API SG150DeviceCapabilityInHomeProperties."""

    inHomeAddress: dict  # noqa: N815
    description: str
    deviceType: str  # noqa: N815
    hasVideo: bool  # noqa: N815
    hasAudio: bool  # noqa: N815
    automationItems: list[dict]  # noqa: N815


class SG150DeviceCapabilityInHome(BaseModel):
    """API SG150DeviceCapabilityInHome."""

    type: Literal["IN_HOME"]
    properties: SG150DeviceCapabilityInHomeProperties


class SG105InHomeAddress(BaseModel):
    """API SG105InHomeAddress."""

    lineAddress: int  # noqa: N815
    deviceAddress: int  # noqa: N815


class SG150AssignedAddress(BaseModel):
    """API SG105InHomeAddress."""

    id: str
    name: str
    inHomeAddress: SG105InHomeAddress  # noqa: N815


class SG150DeviceCapabilityInHomeVirtualProperties(BaseModel):
    """API SG150DeviceCapabilityInHomeVirtualProperties."""

    addressAssigned: bool  # noqa: N815
    assignedAddress: SG150AssignedAddress | None  # noqa: N815


class SG150DeviceCapabilityInHomeVirtual(BaseModel):
    """API SG150DeviceCapabilityInHomeVirtual."""

    type: Literal["IN_HOME_VIRTUAL"]
    properties: SG150DeviceCapabilityInHomeVirtualProperties


class SG150DeviceCapabilityVideoExtractionProperties(BaseModel):
    """API SG150DeviceCapabilityVideoExtractionProperties."""

    enabled: bool
    type: Literal["MJPEG_STREAM", "SNAPSHOT"]
    url: str


class SG150DeviceCapabilityVideoExtraction(BaseModel):
    """API SG150DeviceCapabilityVideoExtraction."""

    type: Literal["VIDEO_EXTRACTION"]
    properties: SG150DeviceCapabilityVideoExtractionProperties


class SG150DeviceCapabilityVideoSenderProperties(BaseModel):
    """API SG150DeviceCapabilityVideoSenderProperties."""

    cameraId: str  # noqa: N815


class SG150DeviceCapabilityVideoSender(BaseModel):
    """API SG150DeviceCapabilityVideoSender."""

    type: Literal["VIDEO_SENDER"]
    properties: SG150DeviceCapabilityVideoSenderProperties


class SG150DeviceCapabilitySusAppProperties(BaseModel):
    """API SG150DeviceCapabilitySusAppProperties."""


class SG150DeviceCapabilitySusApp(BaseModel):
    """API SG150DeviceCapabilitySusApp."""

    type: Literal["SUS_APP"]
    properties: SG150DeviceCapabilitySusAppProperties


class SG150DeviceCapabilityAutomationTileProperties(BaseModel):
    """API SG150DeviceCapabilityAutomationTileProperties."""

    assignedTiles: list[dict]  # noqa: N815


class SG150DeviceCapabilityAutomationTile(BaseModel):
    """API SG150DeviceCapabilityAutomationTile."""

    type: Literal["AUTOMATION_TILE"]
    properties: SG150DeviceCapabilityAutomationTileProperties


class SG150DeviceCapability(RootModel):
    """API SG150DeviceCapability."""

    root: (
        SG150DeviceCapabilityPhoneEndpoint
        | SG150DeviceCapabilityCTIPhone
        | SG150DeviceCapabilityInHome
        | SG150DeviceCapabilityInHomeVirtual
        | SG150DeviceCapabilityVideoExtraction
        | SG150DeviceCapabilityVideoSender
        | SG150DeviceCapabilitySusApp
        | SG150DeviceCapabilityAutomationTile
    ) = Field(discriminator="type")

    def __getattr__(self, name: str) -> Any:
        """Redirects to the correct capability."""
        return getattr(self.root, name)


class SG150DeviceType(str, Enum):
    """API SG150DeviceType."""

    PBXPHONE = "PBXPHONE"
    INHOME = "INHOME"
    SUSAPP = "SUSAPP"


class SG150Device(BaseModel):
    """API SG150Device."""

    id: str
    name: str
    type: SG150DeviceType
    capabilities: list[SG150DeviceCapability]


class SG150Devices(BaseModel):
    """API SG150Devices."""

    devices: list[SG150Device]


class OAuthTokenResponse(BaseModel):
    """API OAuthTokenResponse."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
