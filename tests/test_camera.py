"""Tests for camera MJPEG still extraction."""

import unittest

from custom_components.sg_150.camera import _async_extract_image_from_mjpeg


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


if __name__ == "__main__":
    unittest.main()
