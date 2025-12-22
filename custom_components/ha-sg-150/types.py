from enum import Enum
from typing import Annotated, Union, Literal, Any
from pydantic import RootModel, BaseModel, Field

from .const import LOGGER


class SG150MaschineInfo(BaseModel):
    machineModel: str
    machineName: str
    machineRevision: str
    productionBatch: int
    macAddress: str


class SG150DeviceCallNumber(BaseModel):
    prefix: str | None
    extension: str | None


class SG150PbxSystem(BaseModel):
    id: str
    name: str
    type: str
    externalExtension: SG150DeviceCallNumber


class SG150DeviceCapabilityPhoneEndpointProperties(BaseModel):
    callNumber: SG150DeviceCallNumber
    isDoor: bool
    pbxSystem: SG150PbxSystem


class SG150DeviceCapabilityPhoneEndpoint(BaseModel):
    type: Literal['PHONE_ENDPOINT']
    properties: SG150DeviceCapabilityPhoneEndpointProperties


class SG150DeviceCapabilityCTIPhoneProperties(BaseModel):
    id: str | None
    name: str | None


class SG150DeviceCapabilityCTIPhone(BaseModel):
    type: Literal['CTI_PHONE']
    properties: SG150DeviceCapabilityCTIPhoneProperties


class SG150DeviceCapabilityInHomeProperties(BaseModel):
    inHomeAddress: dict
    description: str
    deviceType: str
    hasVideo: bool
    hasAudio: bool
    automationItems: list[dict]


class SG150DeviceCapabilityInHome(BaseModel):
    type: Literal['IN_HOME']
    properties: SG150DeviceCapabilityInHomeProperties


class SG105InHomeAddress(BaseModel):
    lineAddress: int
    deviceAddress: int


class SG150AssignedAddress(BaseModel):
    id: str
    name: str
    inHomeAddress: SG105InHomeAddress


class SG150DeviceCapabilityInHomeVirtualProperties(BaseModel):
    addressAssigned: bool
    assignedAddress: SG150AssignedAddress | None


class SG150DeviceCapabilityInHomeVirtual(BaseModel):
    type: Literal['IN_HOME_VIRTUAL']
    properties: SG150DeviceCapabilityInHomeVirtualProperties


class SG150DeviceCapabilityVideoExtractionProperties(BaseModel):
    enabled: bool
    type: Literal['MJPEG_STREAM'] | Literal['SNAPSHOT']
    url: str


class SG150DeviceCapabilityVideoExtraction(BaseModel):
    type: Literal['VIDEO_EXTRACTION']
    properties: SG150DeviceCapabilityVideoExtractionProperties


class SG150DeviceCapabilityVideoSenderProperties(BaseModel):
    cameraId: str


class SG150DeviceCapabilityVideoSender(BaseModel):
    type: Literal['VIDEO_SENDER']
    properties: SG150DeviceCapabilityVideoSenderProperties


class SG150DeviceCapabilitySusAppProperties(BaseModel):
    pass


class SG150DeviceCapabilitySusApp(BaseModel):
    type: Literal['SUS_APP']
    properties: SG150DeviceCapabilitySusAppProperties


class SG150DeviceCapabilityAutomationTileProperties(BaseModel):
    assignedTiles: list[dict]


class SG150DeviceCapabilityAutomationTile(BaseModel):
    type: Literal['AUTOMATION_TILE']
    properties: SG150DeviceCapabilityAutomationTileProperties


class SG150DeviceCapability(RootModel):
    root: SG150DeviceCapabilityPhoneEndpoint | \
        SG150DeviceCapabilityCTIPhone | \
        SG150DeviceCapabilityInHome | \
        SG150DeviceCapabilityInHomeVirtual | \
        SG150DeviceCapabilityVideoExtraction | \
        SG150DeviceCapabilityVideoSender | \
        SG150DeviceCapabilitySusApp | \
        SG150DeviceCapabilityAutomationTile = Field(discriminator="type")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.root, name)


class SG150DeviceType(str, Enum):
    PBXPHONE = 'PBXPHONE'
    INHOME = 'INHOME'
    SUSAPP = 'SUSAPP'


class SG150Device(BaseModel):
    id: str
    name: str
    type: SG150DeviceType
    capabilities: list[SG150DeviceCapability]


class SG150Devices(BaseModel):
    devices: list[SG150Device]


class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
