"""Sample API Client."""

from __future__ import annotations

import socket
from hashlib import sha256
from time import time
from typing import Any

import aiohttp
import async_timeout

from .const import LOGGER
from .types import OAuthTokenResponse, SG150Devices, SG150MaschineInfo


class SG150ApiClientError(Exception):
    """Exception to indicate a general API error."""


class SG150ApiClientCommunicationError(
    SG150ApiClientError,
):
    """Exception to indicate a communication error."""


class SG150ApiClientAuthenticationError(
    SG150ApiClientError,
):
    """Exception to indicate an authentication error."""


def _verify_response_or_raise(response: aiohttp.ClientResponse) -> None:
    """Verify that the response is valid."""
    if response.status in (401, 403):
        msg = "Invalid credentials"
        raise SG150ApiClientAuthenticationError(
            msg,
        )
    response.raise_for_status()


class SG150ApiClient:
    """Sample API Client."""

    def __init__(
        self,
        host_address: str,
        port: int,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
    ) -> None:
        """Sample API Client."""
        self._access_token = None
        self._username = username
        self._password = password
        self._port = port
        self._host_address = host_address
        self._session = session
        self._next_refresh_at = 0
        LOGGER.info(
            "SG150ApiClient initialized for host %s:%i (username:%s)",
            host_address,
            port,
            username,
        )

    @staticmethod
    def hash_password(password: str) -> str:
        """Create a hashed version of the password."""
        return sha256(password.encode("utf-8")).hexdigest().upper()

    async def authenticate(self) -> str:
        """Authenticate with the API."""
        if not hasattr(self, "_access_token") or int(time()) >= self._next_refresh_at:
            form_data = aiohttp.FormData()
            form_data.add_field("grant_type", "password")
            form_data.add_field("client_id", "dcip2web")
            form_data.add_field("username", self._username)
            form_data.add_field("password", self._password)

            response = OAuthTokenResponse(
                **await self._api_wrapper(
                    method="POST", route="oauth/token", data=form_data
                )
            )
            self._access_token = response.access_token
            self._next_refresh_at = int(time()) + response.expires_in - 10

        return self._access_token

    async def async_get_in_home_callable(self) -> SG150Devices:
        """Get in-home callable information from the API."""
        return SG150Devices(
            **await self._api_wrapper(
                method="GET",
                route="system/devices",
                authenticate=True,
            )
        )

    async def async_get_machine_info(self) -> SG150MaschineInfo:
        """Get machine information from the API."""
        return SG150MaschineInfo(
            **await self._api_wrapper(
                method="GET",
                route="system/machineInfo",
                authenticate=True,
            )
        )

    async def _api_wrapper(
        self,
        method: str,
        route: str,
        data: dict | None = None,
        headers: dict | None = None,
        authenticate: bool = False,  # noqa: FBT001, FBT002
    ) -> dict[str, Any]:
        """Get information from the API."""
        try:
            if authenticate:
                await self.authenticate()
                headers = headers or {}
                headers.update(
                    {
                        "Authorization": f"Bearer {self._access_token}",
                    }
                )
            async with async_timeout.timeout(10):
                response = await self._session.request(
                    method=method,
                    url=f"http://{self._host_address}:{self._port}/api/op/v1.0/{route}",
                    headers=headers,
                    data=data,
                )
                _verify_response_or_raise(response)
                return await response.json()

        except TimeoutError as exception:
            msg = f"Timeout error fetching information - {exception}"
            raise SG150ApiClientCommunicationError(
                msg,
            ) from exception
        except (aiohttp.ClientError, socket.gaierror) as exception:
            msg = f"Error fetching information - {exception}"
            raise SG150ApiClientCommunicationError(
                msg,
            ) from exception
        except Exception as exception:  # pylint: disable=broad-except
            msg = f"Something really wrong happened! - {exception}"
            raise SG150ApiClientError(
                msg,
            ) from exception
