"""Tests for camera MJPEG still extraction and the camera's HTTP stream."""

from __future__ import annotations

import asyncio
import itertools
import time
import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

import httpx
import pytest
from homeassistant.components.camera import async_get_image
from homeassistant.exceptions import HomeAssistantError

from custom_components.sg_150 import camera, talkback
from custom_components.sg_150.camera import (
    _async_extract_image_from_mjpeg,
    _mjpeg_frames,
)
from tests.test_entities import entity_id

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from homeassistant.core import HomeAssistant


async def _chunks(*chunks: bytes) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk


async def _frames(*chunks: bytes) -> list[bytes]:
    return [frame async for frame in _mjpeg_frames(_chunks(*chunks))]


class CameraTests(unittest.IsolatedAsyncioTestCase):
    """Camera-related regression tests."""

    async def test_extract_image_from_mjpeg(
        self,
    ) -> None:
        """A MJPEG response should return a valid frame."""

        async def stream() -> object:
            payload = b"".join(
                [
                    b"--ssssg\r\n",
                    b"Content-Length: 17983\r\n",
                    b"Content-Type: image/jpeg\r\n\r\n",
                    b"\xff\xd8frame-1\xff\xd9\r\n",
                    b"--ssssg\r\n",
                    b"Content-Length: 16737\r\n",
                    b"Content-Type: image/jpeg\r\n\r\n",
                    b"\xff\xd8frame-2\xff\xd9\r\n",
                    b"--ssssg\r\n",
                    b"Content-Length: 17638\r\n",
                    b"Content-Type: image/jpeg\r\n\r\n",
                    b"\xff\xd8frame-3\xff\xd9\r\n",
                    b"--ssssg\r\n",
                    b"Content-Length: 18093\r\n",
                    b"Content-Type: image/jpeg\r\n\r\n",
                    b"\xff\xd8frame-4\xff\xd9\r\n",
                ]
            )
            yield payload

        result = await _async_extract_image_from_mjpeg(stream())

        assert result == b"\xff\xd8frame-3\xff\xd9"

    async def test_markers_split_across_chunks(self) -> None:
        """Start and end markers may be cut between two chunks."""
        assert await _frames(
            b"junk\xff", b"\xd8a", b"b\xff", b"\xd9\xff\xd8c\xff\xd9"
        ) == [
            b"\xff\xd8ab\xff\xd9",
            b"\xff\xd8c\xff\xd9",
        ]

    async def test_frame_without_end_marker_is_dropped(self) -> None:
        """A frame beyond MAX_FRAME_BYTES is dropped and the next one still found."""
        with patch.object(camera, "MAX_FRAME_BYTES", 16):
            frames = await _frames(
                b"\xff\xd8", b"x" * 10, b"y" * 10, b"\xff\xd8ok\xff\xd9"
            )

        assert frames == [b"\xff\xd8ok\xff\xd9"]


class VideoSourceTests(unittest.IsolatedAsyncioTestCase):
    """Reconnecting to a failing camera stream."""

    async def test_failures_back_off_and_warn_once(self) -> None:
        """Repeated failures log one warning and wait longer each time."""
        attempts: list[float] = []

        async def failing() -> AsyncIterator[bytes]:
            attempts.append(time.monotonic())
            msg = "camera offline"
            raise httpx.ConnectError(msg)
            yield b""  # pragma: no cover

        source = talkback.VideoSource(failing)
        with (
            patch.multiple(talkback, RECONNECT_DELAY=0.01, MAX_RECONNECT_DELAY=0.08),
            self.assertLogs("custom_components.sg_150", "DEBUG") as logs,
        ):
            track = source.track()
            await asyncio.sleep(0.2)
            source.remove(track)

        warnings = [r for r in logs.records if r.levelname == "WARNING"]
        assert len(warnings) == 1
        gaps = [b - a for a, b in itertools.pairwise(attempts)]
        assert len(gaps) >= 3
        assert gaps[2] > gaps[0] * 2


def _stream_client(handler: Callable[[httpx.Request], httpx.Response]) -> Callable:
    def client(_: HomeAssistant) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return client


class _Trickle(httpx.AsyncByteStream):
    """A response body that never delivers a whole frame."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while True:
            await asyncio.sleep(0.01)
            yield b"--boundary\r\n"


@pytest.mark.usefixtures("setup_integration")
async def test_snapshot_of_an_error_page_fails(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """An HTTP error is not scanned for JPEG markers."""
    page = b"\xff\xd8not an image\xff\xd9" * 5
    with (
        patch.object(
            camera,
            "get_async_client",
            _stream_client(lambda _: httpx.Response(500, content=page)),
        ),
        pytest.raises(HomeAssistantError),
    ):
        await async_get_image(hass, entity_id(hass, "camera", "door-frontCamera"))

    assert "500" in caplog.text


@pytest.mark.usefixtures("setup_integration")
async def test_snapshot_has_an_overall_deadline(
    hass: HomeAssistant, caplog: pytest.LogCaptureFixture
) -> None:
    """A stream that keeps trickling without frames gives up after TIMEOUT."""
    with (
        patch.object(camera, "TIMEOUT", 0.1),
        patch.object(
            camera,
            "get_async_client",
            _stream_client(lambda _: httpx.Response(200, stream=_Trickle())),
        ),
        pytest.raises(HomeAssistantError),
    ):
        await async_get_image(
            hass, entity_id(hass, "camera", "door-frontCamera"), timeout=2
        )

    assert "Timeout getting camera image" in caplog.text


if __name__ == "__main__":
    unittest.main()
