"""Adds config flow for Blueprint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import (
    SG150ApiClient,
    SG150ApiClientAuthenticationError,
    SG150ApiClientCommunicationError,
    SG150ApiClientError,
)
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
    LOGGER,
)

MIN_RTP_PORT = 1024
MAX_RTP_PORT = 65535

if TYPE_CHECKING:
    from collections.abc import Mapping


class SG150FlowHandler(config_entries.ConfigFlow, domain=DOMAIN):  # pylint: disable=abstract-method
    """Config flow for Blueprint."""

    VERSION = 1

    def __init__(self) -> None:
        """Init the FlowHandler."""
        super().__init__()
        self._data: dict[str, any] = {}

    @staticmethod
    @callback
    def async_get_options_flow(
        _: config_entries.ConfigEntry,
    ) -> SG150FlowHandler:
        """Get the options flow for this handler."""
        return SG150OptionsFlowHandler()

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> config_entries.ConfigFlowResult:
        """Handle a flow initialized by the user."""
        errors = {}

        if user_input is not None:
            host_address = user_input[CONF_HOST_ADDRESS]
            if await self.async_set_unique_id(host_address.lower()):
                self._abort_if_unique_id_configured()

            username = user_input[CONF_USERNAME]
            password = SG150ApiClient.hash_password(user_input[CONF_PASSWORD])
            errors = await self._async_check_credentials(
                host_address=host_address, username=username, password=password
            )
            if not errors:
                self._data[CONF_HOST_ADDRESS] = host_address
                self._data[CONF_USERNAME] = username
                self._data[CONF_PASSWORD] = password
                return await self.async_step_user_options(user_options=None)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(await self.get_user_config_schema(user_input)),
            errors=errors,
        )

    async def async_step_user_options(
        self, user_options: dict[str, any] | None = None
    ) -> config_entries.FlowResult:
        """Configure user optons."""
        errors = validate_options(user_options) if user_options else {}
        if user_options and not errors:
            return self.async_create_entry(
                title=self._data[CONF_HOST_ADDRESS].lower(),
                data=self._data,
                options=user_options,
            )

        return self.async_show_form(
            step_id="user_options",
            data_schema=vol.Schema(await get_options_schema(user_options)),
            errors=errors,
        )

    async def get_user_config_schema(self, entry: dict | None = None) -> dict:
        """Create the config schema dictionary."""
        if entry is None:
            entry = {}
        return {
            vol.Required(
                CONF_HOST_ADDRESS,
                default=(entry or {}).get(CONF_HOST_ADDRESS, vol.UNDEFINED),
            ): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT),
            ),
            vol.Required(
                CONF_USERNAME, default=(entry or {}).get(CONF_USERNAME, "admin")
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.TEXT,
                ),
            ),
            vol.Required(
                CONF_PASSWORD, default=(entry or {}).get(CONF_PASSWORD, vol.UNDEFINED)
            ): selector.TextSelector(
                selector.TextSelectorConfig(
                    type=selector.TextSelectorType.PASSWORD,
                ),
            ),
        }

    async def async_step_reauth(
        self, _: Mapping[str, Any]
    ) -> config_entries.ConfigFlowResult:
        """Ask for new credentials after the gateway rejected the stored ones."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict | None = None
    ) -> config_entries.ConfigFlowResult:
        """Check the new credentials, store them and reload the entry."""
        entry = self._get_reauth_entry()
        errors = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = SG150ApiClient.hash_password(user_input[CONF_PASSWORD])
            errors = await self._async_check_credentials(
                host_address=entry.data[CONF_HOST_ADDRESS],
                username=username,
                password=password,
            )
            if not errors:
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={CONF_USERNAME: username, CONF_PASSWORD: password},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME, default=entry.data.get(CONF_USERNAME, "admin")
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT
                        ),
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        ),
                    ),
                }
            ),
            description_placeholders={"host": entry.data[CONF_HOST_ADDRESS]},
            errors=errors,
        )

    async def _async_check_credentials(
        self, host_address: str, username: str, password: str
    ) -> dict[str, str]:
        """Authenticate against the gateway and return form errors, if any."""
        client = SG150ApiClient(
            host_address=host_address,
            port=API_PORT,
            username=username,
            password=password,
            session=async_create_clientsession(self.hass),
        )
        try:
            await client.authenticate()
        except SG150ApiClientAuthenticationError as exception:
            LOGGER.warning(exception)
            return {"base": "auth"}
        except SG150ApiClientCommunicationError as exception:
            LOGGER.error(exception)
            return {"base": "connection"}
        except SG150ApiClientError as exception:
            LOGGER.exception(exception)
            return {"base": "unknown"}
        return {}


class SG150OptionsFlowHandler(config_entries.OptionsFlowWithReload):
    """Handles the options flow; changed options reload the entry."""

    async def async_step_init(
        self, user_input: dict[str, any] | None = None
    ) -> config_entries.FlowResult:
        """Configure options."""
        existing_options = self.config_entry.options.copy()
        errors = validate_options(user_input) if user_input else {}

        if user_input and not errors:
            return self.async_create_entry(title="", data=existing_options | user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                await get_options_schema(user_input or self.config_entry.options)
            ),
            errors=errors,
        )


def validate_options(options: Mapping[str, Any]) -> dict[str, str]:
    """Return form errors for the options, if any."""
    try:
        low = int(options.get(CONF_RTP_PORT_MIN, DEFAULT_RTP_PORT_MIN))
        high = int(options.get(CONF_RTP_PORT_MAX, DEFAULT_RTP_PORT_MAX))
    except ValueError:
        return {"base": "rtp_ports"}
    if not MIN_RTP_PORT <= low <= high <= MAX_RTP_PORT:
        return {"base": "rtp_ports"}
    return {}


async def get_options_schema(entry: dict | None = None) -> dict:
    """Create the options schema dictionary."""
    return {
        vol.Required(
            CONF_SIP_CALLER_IP,
            default=(entry or {}).get(CONF_SIP_CALLER_IP, vol.UNDEFINED),
        ): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.TEXT),
        ),
        vol.Required(
            CONF_SIP_USER, default=(entry or {}).get(CONF_SIP_USER, vol.UNDEFINED)
        ): selector.TextSelector(
            selector.TextSelectorConfig(
                type=selector.TextSelectorType.TEXT,
            ),
        ),
        vol.Required(
            CONF_SIP_PASSWORD,
            default=(entry or {}).get(CONF_SIP_PASSWORD, vol.UNDEFINED),
        ): selector.TextSelector(
            selector.TextSelectorConfig(
                type=selector.TextSelectorType.PASSWORD,
            ),
        ),
        vol.Required(
            CONF_SIP_NUMBER, default=(entry or {}).get(CONF_SIP_NUMBER, vol.UNDEFINED)
        ): selector.TextSelector(
            selector.TextSelectorConfig(
                type=selector.TextSelectorType.TEXT,
            ),
        ),
        vol.Required(
            CONF_SIP_PORT, default=(entry or {}).get(CONF_SIP_PORT, vol.UNDEFINED)
        ): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.NUMBER),
        ),
        vol.Optional(
            CONF_SIP_AUTO_ANSWER, default=(entry or {}).get(CONF_SIP_AUTO_ANSWER, True)
        ): selector.BooleanSelector(),
        vol.Optional(
            CONF_TWO_WAY_AUDIO, default=(entry or {}).get(CONF_TWO_WAY_AUDIO, False)
        ): selector.BooleanSelector(),
        vol.Optional(
            CONF_RTP_PORT_MIN,
            default=str((entry or {}).get(CONF_RTP_PORT_MIN, DEFAULT_RTP_PORT_MIN)),
        ): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.NUMBER),
        ),
        vol.Optional(
            CONF_RTP_PORT_MAX,
            default=str((entry or {}).get(CONF_RTP_PORT_MAX, DEFAULT_RTP_PORT_MAX)),
        ): selector.TextSelector(
            selector.TextSelectorConfig(type=selector.TextSelectorType.NUMBER),
        ),
    }
