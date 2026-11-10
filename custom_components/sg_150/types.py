"""
Types used in the API.

These are used as return types of various API-Calls
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Discriminator, Field, RootModel, Tag


class SG150MaschineInfo(BaseModel):
    """API Maschine Info."""

    machineModel: str | None = None  # noqa: N815
    machineName: str  # noqa: N815
    machineRevision: str  # noqa: N815
    productionBatch: int | None = None  # noqa: N815
    macAddress: str  # noqa: N815


class SG150DeviceCallNumber(BaseModel):
    """API SG150DeviceCallNumber."""

    prefix: str | None
    extension: str | None

    @property
    def dialable(self) -> str:
        """Return the dial string sent to the gateway (prefix + extension)."""
        return f"{self.prefix or ''}{self.extension or ''}"

    @property
    def display(self) -> str:
        """Return the call number formatted for display."""
        return " ".join(part for part in (self.prefix, self.extension) if part)


class SG150PbxSystem(BaseModel):
    """API SG150PbxSystem."""

    id: str | None = None
    name: str | None = None
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

    inHomeAddress: dict | None = None  # noqa: N815
    description: str | None = None
    deviceType: str  # noqa: N815
    hasVideo: bool | None = None  # noqa: N815
    hasAudio: bool | None = None  # noqa: N815
    automationItems: list[dict] | None = None  # noqa: N815


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

    addressAssigned: bool | None = None  # noqa: N815
    assignedAddress: SG150AssignedAddress | None = None  # noqa: N815


class SG150DeviceCapabilityInHomeVirtual(BaseModel):
    """API SG150DeviceCapabilityInHomeVirtual."""

    type: Literal["IN_HOME_VIRTUAL"]
    properties: SG150DeviceCapabilityInHomeVirtualProperties


class SG150DeviceCapabilityVideoExtractionProperties(BaseModel):
    """API SG150DeviceCapabilityVideoExtractionProperties."""

    enabled: bool | None = None
    # Known values are MJPEG_STREAM and SNAPSHOT; kept open for new firmware.
    type: str
    url: str


class SG150DeviceCapabilityVideoExtraction(BaseModel):
    """API SG150DeviceCapabilityVideoExtraction."""

    type: Literal["VIDEO_EXTRACTION"]
    properties: SG150DeviceCapabilityVideoExtractionProperties


class SG150DeviceCapabilityVideoSenderProperties(BaseModel):
    """API SG150DeviceCapabilityVideoSenderProperties."""

    cameraId: str | None = None  # noqa: N815


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

    assignedTiles: list[dict] | None = None  # noqa: N815


class SG150DeviceCapabilityAutomationTile(BaseModel):
    """API SG150DeviceCapabilityAutomationTile."""

    type: Literal["AUTOMATION_TILE"]
    properties: SG150DeviceCapabilityAutomationTileProperties


class SG150DeviceCapabilityAutomationProperties(BaseModel):
    """API SG150DeviceCapabilityAutomationProperties."""

    controllerId: str | None = None  # noqa: N815
    automationItems: list[dict] | None = None  # noqa: N815


class SG150DeviceCapabilityAutomation(BaseModel):
    """API SG150DeviceCapabilityAutomation."""

    type: Literal["AUTOMATION"]
    properties: SG150DeviceCapabilityAutomationProperties


class SG150DeviceCapabilityUnknown(BaseModel):
    """A capability type this integration does not know, kept as is."""

    model_config = ConfigDict(extra="allow")

    type: str


_KNOWN_CAPABILITIES = frozenset(
    {
        "PHONE_ENDPOINT",
        "CTI_PHONE",
        "IN_HOME",
        "IN_HOME_VIRTUAL",
        "VIDEO_EXTRACTION",
        "VIDEO_SENDER",
        "SUS_APP",
        "AUTOMATION",
        "AUTOMATION_TILE",
    }
)


def _capability_tag(value: Any) -> str:
    """Return the capability's type, or UNKNOWN for one added by new firmware."""
    kind = (
        value.get("type") if isinstance(value, dict) else getattr(value, "type", None)
    )
    return kind if kind in _KNOWN_CAPABILITIES else "UNKNOWN"


class SG150DeviceCapability(RootModel):
    """API SG150DeviceCapability."""

    root: Annotated[
        Annotated[SG150DeviceCapabilityPhoneEndpoint, Tag("PHONE_ENDPOINT")]
        | Annotated[SG150DeviceCapabilityCTIPhone, Tag("CTI_PHONE")]
        | Annotated[SG150DeviceCapabilityInHome, Tag("IN_HOME")]
        | Annotated[SG150DeviceCapabilityInHomeVirtual, Tag("IN_HOME_VIRTUAL")]
        | Annotated[SG150DeviceCapabilityVideoExtraction, Tag("VIDEO_EXTRACTION")]
        | Annotated[SG150DeviceCapabilityVideoSender, Tag("VIDEO_SENDER")]
        | Annotated[SG150DeviceCapabilitySusApp, Tag("SUS_APP")]
        | Annotated[SG150DeviceCapabilityAutomation, Tag("AUTOMATION")]
        | Annotated[SG150DeviceCapabilityAutomationTile, Tag("AUTOMATION_TILE")]
        | Annotated[SG150DeviceCapabilityUnknown, Tag("UNKNOWN")],
        Discriminator(_capability_tag),
    ]


def _find_capability[T: BaseModel](
    capabilities: list[SG150DeviceCapability], kind: type[T]
) -> T | None:
    """Return the first capability of the given kind, if any."""
    return next(
        (
            capability.root
            for capability in capabilities
            if isinstance(capability.root, kind)
        ),
        None,
    )


class SG150DeviceType(StrEnum):
    """API SG150DeviceType."""

    PBXPHONE = "PBXPHONE"
    INHOME = "INHOME"
    SUSAPP = "SUSAPP"


class SG150Device(BaseModel):
    """API SG150Device."""

    id: str
    name: str
    # Without left_to_right, pydantic's smart mode would prefer the plain str.
    type: SG150DeviceType | str = Field(union_mode="left_to_right")
    capabilities: list[SG150DeviceCapability]

    @property
    def phone_endpoint(self) -> SG150DeviceCapabilityPhoneEndpointProperties | None:
        """Return the PHONE_ENDPOINT properties, if the device has one."""
        capability = _find_capability(
            self.capabilities, SG150DeviceCapabilityPhoneEndpoint
        )
        return capability.properties if capability else None

    @property
    def video_extraction(
        self,
    ) -> SG150DeviceCapabilityVideoExtractionProperties | None:
        """Return the VIDEO_EXTRACTION properties, if the device has one."""
        capability = _find_capability(
            self.capabilities, SG150DeviceCapabilityVideoExtraction
        )
        return capability.properties if capability else None

    @property
    def mjpeg_stream_url(self) -> str | None:
        """Return the URL of the device's MJPEG stream, the camera's source."""
        video_extraction = self.video_extraction
        if video_extraction is None or video_extraction.type != "MJPEG_STREAM":
            return None
        return video_extraction.url

    @property
    def in_home(self) -> SG150DeviceCapabilityInHomeProperties | None:
        """Return the IN_HOME properties, if the device has one."""
        capability = _find_capability(self.capabilities, SG150DeviceCapabilityInHome)
        return capability.properties if capability else None

    @property
    def is_door(self) -> bool:
        """Return whether the device is a door station."""
        return self.phone_endpoint is not None and self.phone_endpoint.isDoor

    @property
    def is_external_pbx_phone(self) -> bool:
        """Return whether the device is a phone on an external PBX system."""
        return (
            self.type == SG150DeviceType.PBXPHONE
            and self.phone_endpoint is not None
            and self.phone_endpoint.pbxSystem.type == "EXTERNAL"
        )


class SG150Devices(BaseModel):
    """API SG150Devices."""

    devices: list[SG150Device]


class OAuthTokenResponse(BaseModel):
    """API OAuthTokenResponse."""

    access_token: str
    token_type: str | None = None
    expires_in: int
    refresh_token: str | None = None


class SG150StoredImage(BaseModel):
    """API SG150StoredImage: a picture the gateway took during a call."""

    id: int
    uid: str
    cameraName: str  # noqa: N815
    timestamp: datetime
    callId: str | None = None  # noqa: N815
    filename: str


class SG150StoredImageContent(SG150StoredImage):
    """API SG150StoredImageContent: a stored image with its base64 content."""

    content: str


class SG150StoredImages(BaseModel):
    """API SG150StoredImages: the image store's reply for one device."""

    images: list[SG150StoredImage]
