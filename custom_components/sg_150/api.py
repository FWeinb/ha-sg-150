"""Client for the SG-150 HTTP API."""

from __future__ import annotations

import asyncio
import binascii
import mimetypes
import socket
from base64 import b64decode
from hashlib import sha256
from time import monotonic
from typing import Any

import aiohttp
from pydantic import BaseModel, ValidationError

from .const import LOGGER
from .types import (
    OAuthTokenResponse,
    SG150Device,
    SG150Devices,
    SG150MaschineInfo,
    SG150StoredImage,
    SG150StoredImageContent,
    SG150StoredImages,
)


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


def _validate[T: BaseModel](model: type[T], response: Any, what: str) -> T:
    """Validate a gateway response, raising SG150ApiClientError if it does not fit."""
    try:
        return model.model_validate(response)
    except (ValidationError, TypeError) as exception:
        msg = f"Unexpected {what} from the gateway - {exception}"
        raise SG150ApiClientError(msg) from exception


class SG150ApiClient:
    """Client for the SG-150 HTTP API."""

    def __init__(
        self,
        host_address: str,
        port: int,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
    ) -> None:
        """Create a client for the gateway at host_address."""
        self._access_token = None
        self._username = username
        self._password = password
        self._port = port
        self._host_address = host_address
        self._session = session
        self._next_refresh_at = 0.0
        self._token_lock = asyncio.Lock()
        self._skipped_devices: set[str | None] = set()
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

    def _has_valid_token(self) -> bool:
        return self._access_token is not None and monotonic() < self._next_refresh_at

    async def authenticate(self) -> str:
        """Authenticate with the API."""
        # Parallel requests (thumbnails in the media browser) share one token request.
        async with self._token_lock:
            if not self._has_valid_token():
                form_data = aiohttp.FormData()
                form_data.add_field("grant_type", "password")
                form_data.add_field("client_id", "dcip2web")
                form_data.add_field("username", self._username)
                form_data.add_field("password", self._password)

                response = _validate(
                    OAuthTokenResponse,
                    await self._api_wrapper(
                        method="POST", route="oauth/token", data=form_data
                    ),
                    "token response",
                )
                self._access_token = response.access_token
                self._next_refresh_at = monotonic() + response.expires_in - 10

            return self._access_token

    async def async_get_in_home_callable(self) -> SG150Devices:
        """
        Get in-home callable information from the API.

        Devices are validated one by one, so a device whose data changed with a
        firmware update is skipped instead of failing the whole list.
        """
        response = await self._api_wrapper(
            method="GET",
            route="system/devices",
            authenticate=True,
        )
        if not isinstance(response, dict) or not isinstance(
            response.get("devices"), list
        ):
            msg = f"Unexpected device list from the gateway - {response!r:.200}"
            raise SG150ApiClientError(msg)

        devices = []
        for raw_device in response["devices"]:
            try:
                devices.append(SG150Device.model_validate(raw_device))
            except (ValidationError, TypeError) as exception:
                device_id = (
                    raw_device.get("id") if isinstance(raw_device, dict) else None
                )
                if device_id not in self._skipped_devices:
                    self._skipped_devices.add(device_id)
                    LOGGER.warning(
                        "Skipping device %s with unexpected data - %s",
                        device_id,
                        exception,
                    )
        return SG150Devices(devices=devices)

    async def async_get_machine_info(self) -> SG150MaschineInfo:
        """Get machine information from the API."""
        return _validate(
            SG150MaschineInfo,
            await self._api_wrapper(
                method="GET",
                route="system/machineInfo",
                authenticate=True,
            ),
            "machine info",
        )

    async def async_trigger_door_opener(self, call_number: str) -> None:
        """
        Trigger the door opener.

        callNumber: The prefix + number of the phone to trigger the door opener.
        """
        await self._api_wrapper(
            method="POST",
            route="in-home/openDoorRequests",
            json={"callNumber": call_number},
            authenticate=True,
        )

    async def async_get_stored_images(self, device_id: str) -> list[SG150StoredImage]:
        """Get the images the gateway stored for calls to a device."""
        response = await self._api_wrapper(
            method="GET",
            route="video/imageStore/images",
            params={"deviceId": device_id},
            authenticate=True,
        )
        return _validate(SG150StoredImages, response, "image list").images

    async def async_get_stored_image(self, uid: str) -> tuple[bytes, str]:
        """
        Download a stored image, returning its bytes and content type.

        The gateway returns the image's metadata with the picture base64 encoded
        in `content`; the content type is taken from the file name.
        """
        response = await self._api_wrapper(
            method="GET",
            route=f"video/imageStore/images/{uid}",
            authenticate=True,
        )
        image = _validate(SG150StoredImageContent, response, "image")

        try:
            body = b64decode(image.content, validate=True)
        except binascii.Error as exception:
            msg = f"Image {uid} has invalid base64 content - {exception}"
            raise SG150ApiClientError(msg) from exception
        if not body:
            msg = f"Image {uid} has no content"
            raise SG150ApiClientError(msg)

        content_type, _ = mimetypes.guess_type(image.filename)
        return body, content_type or "image/jpeg"

    async def async_trigger_light_switch(self) -> None:
        """Trigger the switch light."""
        await self._api_wrapper(
            method="POST",
            route="in-home/switchLightRequests",
            authenticate=True,
        )

    async def _api_wrapper(  # noqa: PLR0913
        self,
        method: str,
        route: str,
        *,
        data: dict | None = None,
        json: dict | None = None,
        params: dict | None = None,
        authenticate: bool = False,
    ) -> Any:
        """
        Call the API and return the decoded JSON response.

        If the gateway rejects a cached token, for example because it rebooted,
        a new token is requested and the request repeated once. Only a rejection
        of the new token raises SG150ApiClientAuthenticationError.
        """
        try:
            if not authenticate:
                return await self._request(
                    method, route, token=None, data=data, json=json, params=params
                )

            cached = self._has_valid_token()
            token = await self.authenticate()
            try:
                return await self._request(
                    method, route, token=token, data=data, json=json, params=params
                )
            except SG150ApiClientAuthenticationError:
                if not cached:
                    raise
                LOGGER.debug("The gateway rejected the cached token, renewing it")
                # Another request may have renewed the token meanwhile.
                if self._access_token == token:
                    self._access_token = None
                token = await self.authenticate()
                return await self._request(
                    method, route, token=token, data=data, json=json, params=params
                )

        except SG150ApiClientError:
            raise
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

    async def _request(  # noqa: PLR0913
        self,
        method: str,
        route: str,
        *,
        token: str | None,
        data: aiohttp.FormData | None,
        json: dict | None,
        params: dict | None,
    ) -> Any:
        """Send one request and return the decoded JSON response."""
        headers = {"Authorization": f"Bearer {token}"} if token else None
        async with (
            asyncio.timeout(10),
            self._session.request(
                method=method,
                url=f"http://{self._host_address}:{self._port}/api/op/v1.0/{route}",
                headers=headers,
                data=data,
                json=json,
                params=params,
            ) as response,
        ):
            _verify_response_or_raise(response)
            return await response.json()
