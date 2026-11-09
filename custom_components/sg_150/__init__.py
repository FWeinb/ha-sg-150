"""
Custom integration for the Siedle Gateway 150 with Home Assistant.

For more details about this integration, please refer to
https://github.com/fweinb/ha-sg-150
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import dns.rdata
import dns.rdataclass
import dns.rdatatype
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.loader import async_get_loaded_integration

from .api import SG150ApiClient
from .const import (
    API_PORT,
    CONF_HOST_ADDRESS,
    CONF_RTP_PORT_MAX,
    CONF_RTP_PORT_MIN,
    CONF_SIP_AUTO_ANSWER,
    CONF_SIP_CALLER_IP,
    CONF_SIP_NUMBER,
    CONF_SIP_PASSWORD,
    CONF_SIP_PORT,
    CONF_SIP_USER,
    CONF_TWO_WAY_AUDIO,
    DEFAULT_RTP_PORT_MAX,
    DEFAULT_RTP_PORT_MIN,
    DOMAIN,
)
from .coordinator import SG150Coordinator
from .data import SG150RuntimeData
from .line import GatewayLine
from .media_source import SG150ImageView
from .services import async_setup_services
from .sip.minisip import MiniSIPServer

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.typing import ConfigType

    from .data import SG150ConfigEntry

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

PLATFORMS: list[Platform] = [
    Platform.EVENT,
    Platform.CAMERA,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
]


# Taken from https://github.com/home-assistant/core/pull/121702/changes
def load_dnspython_rdata_classes() -> None:
    """Load dnspython rdata classes used by aioice."""
    # aioice's mDNS records use class IN with the cache-flush bit set, which
    # dnspython caches separately from IN and would otherwise import on demand.
    for rdclass in (dns.rdataclass.IN, dns.rdataclass.IN | 0x8000):
        for rdtype in dns.rdatatype.RdataType:
            if not dns.rdatatype.is_metatype(rdtype) or rdtype == dns.rdatatype.OPT:
                dns.rdata.get_rdata_class(rdclass, rdtype)  # type: ignore[no-untyped-call]


async def async_setup(hass: HomeAssistant, _: ConfigType) -> bool:
    """Register the services and the image view once per Home Assistant instance."""
    async_setup_services(hass)
    hass.http.register_view(SG150ImageView(hass))
    return True


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SG150ConfigEntry,
) -> bool:
    """Set up this integration using UI."""
    # Workaround to avoid blocking imports from dnspython (https://github.com/rthalley/dnspython/issues/1083)
    await hass.async_add_executor_job(load_dnspython_rdata_classes)

    coordinator = SG150Coordinator(hass=hass)

    client = SG150ApiClient(
        host_address=entry.data.get(CONF_HOST_ADDRESS),
        port=API_PORT,
        username=entry.data.get(CONF_USERNAME),
        password=entry.data.get(CONF_PASSWORD),
        session=async_get_clientsession(hass),
    )

    users = {}
    users[entry.options.get(CONF_SIP_USER)] = entry.options.get(CONF_SIP_PASSWORD)
    server = MiniSIPServer(
        call_host=entry.options.get(CONF_SIP_CALLER_IP),
        users=users,
        port=int(entry.options.get(CONF_SIP_PORT)),
        rtp_ports=range(
            int(entry.options.get(CONF_RTP_PORT_MIN, DEFAULT_RTP_PORT_MIN)),
            int(entry.options.get(CONF_RTP_PORT_MAX, DEFAULT_RTP_PORT_MAX)) + 1,
        ),
        # Accept the gateway's calls before it registers again after a restart.
        trusted_hosts=[entry.data.get(CONF_HOST_ADDRESS)],
    )

    line = GatewayLine(
        server,
        user=entry.options.get(CONF_SIP_USER),
        number=entry.options.get(CONF_SIP_NUMBER),
        auto_answer=entry.options.get(CONF_SIP_AUTO_ANSWER, True),
        devices=lambda: coordinator.data.devices if coordinator.data else [],
        # Without auto answer, ring along so the camera's talk button can answer.
        ring_along=entry.options.get(CONF_TWO_WAY_AUDIO, False),
    )

    entry.runtime_data = SG150RuntimeData(
        line=line,
        client=client,
        integration=async_get_loaded_integration(hass, entry.domain),
        coordinator=coordinator,
    )

    await coordinator.async_config_entry_first_refresh()
    await coordinator.async_register_gateway_device()

    try:
        await line.start()
    except OSError as err:
        msg = f"Could not listen on SIP port {server.port}: {err}"
        raise ConfigEntryNotReady(msg) from err

    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except BaseException:
        await line.stop()
        raise

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: SG150ConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.line.stop()
    return unloaded
