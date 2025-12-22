"""Adds config flow for Blueprint."""

from __future__ import annotations

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
    CONF_SIP_CALLER_IP,
    CONF_SIP_NUMBER,
    CONF_SIP_PASSWORD,
    CONF_SIP_PORT,
    CONF_SIP_USER,
    DOMAIN,
    LOGGER,
)


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
            try:
                host_address = user_input[CONF_HOST_ADDRESS]
                if await self.async_set_unique_id(host_address.lower()):
                    self._abort_if_unique_id_configured()
                else:
                    username = user_input[CONF_USERNAME]
                    password = SG150ApiClient.hash_password(user_input[CONF_PASSWORD])

                    self._data[CONF_HOST_ADDRESS] = host_address
                    self._data[CONF_USERNAME] = username
                    self._data[CONF_PASSWORD] = password

                    await self._test_credentials(
                        host_address=host_address,
                        username=username,
                        password=password,
                    )

                    return await self.async_step_user_options(user_options=None)
            except SG150ApiClientAuthenticationError as exception:
                LOGGER.warning(exception)
                errors["base"] = "auth"
            except SG150ApiClientCommunicationError as exception:
                LOGGER.error(exception)
                errors["base"] = "connection"
            except SG150ApiClientError as exception:
                LOGGER.exception(exception)
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(await self.get_user_config_schema(user_input)),
            errors=errors,
        )

    async def async_step_user_options(
        self, user_options: dict[str, any] | None = None
    ) -> config_entries.FlowResult:
        """Configure user optons."""
        if user_options:
            return self.async_create_entry(
                title=self._data[CONF_HOST_ADDRESS].lower(),
                data=self._data,
                options=user_options,
            )

        return self.async_show_form(
            step_id="user_options",
            data_schema=vol.Schema(await get_options_schema(user_options)),
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

    async def _test_credentials(
        self, host_address: str, username: str, password: str
    ) -> None:
        """Validate credentials."""
        client = SG150ApiClient(
            host_address=host_address,
            port=API_PORT,
            username=username,
            password=password,
            session=async_create_clientsession(self.hass),
        )
        await client.authenticate()


class SG150OptionsFlowHandler(config_entries.OptionsFlow):
    """Handles the options flow."""

    async def async_step_init(
        self, user_input: dict[str, any] | None = None
    ) -> config_entries.FlowResult:
        """Configure options."""
        existing_options = self.config_entry.options.copy()

        if user_input:
            return self.async_create_entry(title="", data=existing_options | user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                await get_options_schema(user_input or self.config_entry.options)
            ),
        )


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
    }
