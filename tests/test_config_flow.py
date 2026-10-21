"""The config and options flows."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from homeassistant.config_entries import SOURCE_USER
from homeassistant.data_entry_flow import FlowResultType

from custom_components.sg_150.api import SG150ApiClient
from custom_components.sg_150.const import (
    CONF_HOST_ADDRESS,
    CONF_SIP_AUTO_ANSWER,
    CONF_SIP_CALLER_IP,
    CONF_SIP_NUMBER,
    CONF_SIP_PASSWORD,
    CONF_SIP_PORT,
    CONF_SIP_USER,
    DOMAIN,
)
from tests.conftest import API_URL, HOST, TOKEN

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from pytest_homeassistant_custom_component.common import MockConfigEntry
    from pytest_homeassistant_custom_component.test_util.aiohttp import (
        AiohttpClientMocker,
    )

    from custom_components.sg_150.sip.minisip import MiniSIPServer

CREDENTIALS = {CONF_HOST_ADDRESS: HOST, "username": "admin", "password": "pw"}
OPTIONS = {
    CONF_SIP_CALLER_IP: "192.0.2.20",
    CONF_SIP_USER: "gateway",
    CONF_SIP_PASSWORD: "secret",
    CONF_SIP_NUMBER: "*2620",
    CONF_SIP_PORT: "5060",
    CONF_SIP_AUTO_ANSWER: False,
}


async def _start(hass: HomeAssistant) -> dict:
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )


async def test_user_flow_creates_entry(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Valid credentials lead to the SIP options and then an entry."""
    aioclient_mock.post(f"{API_URL}/oauth/token", json=TOKEN)

    result = await _start(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], CREDENTIALS
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user_options"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], OPTIONS)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == HOST
    assert result["data"] == {
        CONF_HOST_ADDRESS: HOST,
        "username": "admin",
        "password": SG150ApiClient.hash_password("pw"),
    }
    assert result["options"] == OPTIONS


@pytest.mark.parametrize(
    ("status", "error"),
    [(401, "auth"), (403, "auth"), (500, "connection")],
)
async def test_user_flow_reports_errors(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    status: int,
    error: str,
) -> None:
    """Rejected credentials and gateway errors are shown on the form."""
    aioclient_mock.post(f"{API_URL}/oauth/token", status=status)

    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], CREDENTIALS
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {"base": error}


async def test_user_flow_aborts_for_configured_gateway(
    hass: HomeAssistant, config_entry: MockConfigEntry
) -> None:
    """The same gateway cannot be added twice."""
    config_entry.add_to_hass(hass)

    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], CREDENTIALS
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_options_flow_updates_options(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    setup_integration: MiniSIPServer,
    sip_servers: list[MiniSIPServer],
) -> None:
    """Changed options are stored and the entry reloads with them."""
    result = await hass.config_entries.options.async_init(config_entry.entry_id)
    assert result["type"] is FlowResultType.FORM

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**config_entry.options, CONF_SIP_NUMBER: "*2621"}
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert config_entry.options[CONF_SIP_NUMBER] == "*2621"
    assert len(sip_servers) == 2
