"""
Tests for Talkback, with an in-process aiortc peer as the browser.

The browser offers like the Home Assistant frontend: a recvonly audio
transceiver to watch, a sendrecv one with a microphone to talk, and a recvonly
video transceiver. The SIP side is a MiniSIPServer on fake transports.
"""

import asyncio
import fractions
import time
import unittest
from collections.abc import AsyncIterator
from unittest.mock import patch

import av
import numpy as np
import pytest
from aiortc import RTCConfiguration, RTCPeerConnection, RTCSessionDescription
from aiortc.mediastreams import MediaStreamError, MediaStreamTrack
from homeassistant.components.camera import WebRTCAnswer, WebRTCMessage

from custom_components.sg_150.line import CallEnded, GatewayLine, LineEvent
from custom_components.sg_150.sip.minisip import MiniSIPServer
from custom_components.sg_150.sip.rtp import (
    PCMA,
    SAMPLES_PER_FRAME,
    RtpPacket,
    g711_decode,
    g711_encode,
)
from custom_components.sg_150.talkback import Talkback, offer_sends_audio
from tests.sip_messages import (
    GATEWAY,
    HA_HOST,
    HA_NUMBER,
    SIP_PASSWORD,
    SIP_USER,
    ack,
    invite,
)
from tests.utils import FakeTransport, fake_rtp_endpoint, load_devices

DOOR = "door-front"
TIMEOUT = 10
TONE = 4000


def _jpeg(width: int = 320, height: int = 240) -> bytes:
    encoder = av.CodecContext.create("mjpeg", "w")
    encoder.width, encoder.height = width, height
    encoder.pix_fmt = "yuvj420p"
    encoder.time_base = fractions.Fraction(1, 15)
    frame = av.VideoFrame.from_ndarray(
        np.full((height, width, 3), 128, dtype=np.uint8), format="rgb24"
    ).reformat(format="yuvj420p")
    return b"".join(bytes(p) for p in [*encoder.encode(frame), *encoder.encode()])


async def _camera() -> AsyncIterator[bytes]:
    jpeg = _jpeg()
    while True:
        yield jpeg
        await asyncio.sleep(1 / 30)


class MicrophoneTrack(MediaStreamTrack):
    """A browser microphone playing a constant tone, 20 ms frames at 8 kHz."""

    kind = "audio"

    def __init__(self) -> None:
        """Start at timestamp zero."""
        super().__init__()
        self._pts = 0
        self._start = time.monotonic()

    async def recv(self) -> av.AudioFrame:
        """Return the next frame of the tone."""
        if self.readyState != "live":
            raise MediaStreamError
        self._pts += SAMPLES_PER_FRAME
        await asyncio.sleep(max(0, self._start + self._pts / 8000 - time.monotonic()))
        frame = av.AudioFrame.from_ndarray(
            np.full((1, SAMPLES_PER_FRAME), TONE, dtype=np.int16),
            format="s16",
            layout="mono",
        )
        frame.sample_rate = 8000
        frame.pts = self._pts
        frame.time_base = fractions.Fraction(1, 8000)
        return frame


class Browser:
    """An aiortc peer that offers like the Home Assistant frontend."""

    def __init__(self, *, talk: bool) -> None:
        """Create the peer, with a microphone if it talks."""
        # No STUN servers: everything runs on this host.
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        if talk:
            self.pc.addTransceiver(MicrophoneTrack(), direction="sendrecv")
        else:
            self.pc.addTransceiver("audio", direction="recvonly")
        self.pc.addTransceiver("video", direction="recvonly")
        self.frames: dict[str, list[av.frame.Frame]] = {"audio": [], "video": []}
        self._tasks: list[asyncio.Task] = []
        self.pc.on("track", self._on_track)

    def _on_track(self, track: MediaStreamTrack) -> None:
        async def read() -> None:
            while True:
                try:
                    self.frames[track.kind].append(await track.recv())
                except MediaStreamError:
                    return

        self._tasks.append(asyncio.create_task(read()))

    async def connect(self, talkback: Talkback, session_id: str) -> str:
        """Send our offer to `talkback` and apply its answer; return the offer."""
        await self.pc.setLocalDescription(await self.pc.createOffer())
        messages: list[WebRTCMessage] = []
        offer = self.pc.localDescription.sdp
        await talkback.handle_offer(session_id, offer, messages.append, [])
        assert isinstance(messages[0], WebRTCAnswer)
        await self.pc.setRemoteDescription(
            RTCSessionDescription(sdp=messages[0].answer, type="answer")
        )
        return offer

    async def close(self) -> None:
        """Close the peer."""
        for task in self._tasks:
            task.cancel()
        await self.pc.close()


async def _until(condition: object) -> None:
    deadline = time.monotonic() + TIMEOUT
    while not condition():
        if time.monotonic() > deadline:
            msg = "condition not met in time"
            raise AssertionError(msg)
        await asyncio.sleep(0.02)


class OfferTests(unittest.TestCase):
    """Telling watching offers from talking ones."""

    def test_offer_sends_audio(self) -> None:
        """Only an active audio section that sends counts as talking."""
        head = "v=0\r\n"
        video = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=recvonly\r\n"

        assert offer_sends_audio(head + "m=audio 9 RTP 0\r\na=sendrecv\r\n" + video)
        assert offer_sends_audio(head + "m=audio 9 RTP 0\r\na=sendonly\r\n")
        assert offer_sends_audio(head + "m=audio 9 RTP 0\r\n")
        assert not offer_sends_audio(head + "m=audio 9 RTP 0\r\na=recvonly\r\n")
        assert not offer_sends_audio(head + "m=audio 0 RTP 0\r\na=sendrecv\r\n")
        assert not offer_sends_audio(head + video.replace("recvonly", "sendrecv"))


# WebRTC needs real sockets for ICE; the Home Assistant test harness blocks them.
@pytest.mark.usefixtures("socket_enabled")
class TalkbackTests(unittest.IsolatedAsyncioTestCase):
    """Talkback bridges browser sessions and the door station's calls."""

    async def asyncSetUp(self) -> None:
        """Create a ring-along line with a talkback for the front door."""
        # Keep ICE on loopback, whatever interfaces this host (or the harness) has.
        loopback = patch("aioice.ice.get_host_addresses", return_value=["127.0.0.1"])
        loopback.start()
        self.addCleanup(loopback.stop)
        self.browsers: list[Browser] = []
        self._setup(auto_answer=False)

    async def asyncTearDown(self) -> None:
        """Close the browsers, the talkback and the line."""
        for browser in self.browsers:
            await browser.close()
        await self.talkback.close()
        await self.line.stop()

    def _setup(self, *, auto_answer: bool) -> None:
        self.server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD},
            host=HA_HOST,
            call_host=HA_HOST,
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.transport = FakeTransport()
        self.server.transport = self.transport
        self.events: list[LineEvent] = []
        self.line = GatewayLine(
            self.server,
            user=SIP_USER,
            number=HA_NUMBER,
            auto_answer=auto_answer,
            ring_along=True,
            devices=load_devices().values,
        )
        self.line.subscribe(self.events.append)
        self.talkback = Talkback(self.line, DOOR, _camera)

    async def _ring(self, call_id: str = "call-1") -> None:
        await self.server.handle_datagram(invite(call_id, "*111", HA_NUMBER), GATEWAY)

    async def _ack(self, call_id: str = "call-1") -> None:
        await self.server.handle_datagram(ack(call_id), GATEWAY)

    def _statuses(self) -> list[str]:
        return [data.split(b"\r\n", 1)[0].decode() for data, _ in self.transport.sent]

    def _requests(self, method: bytes) -> int:
        return sum(data.startswith(method) for data, _ in self.transport.sent)

    async def _browser(self, session_id: str, *, talk: bool) -> Browser:
        browser = Browser(talk=talk)
        self.browsers.append(browser)
        await browser.connect(self.talkback, session_id)
        return browser

    async def test_watching_gets_video_and_leaves_the_call_ringing(self) -> None:
        """A recvonly session sees the camera but never answers."""
        await self._ring()

        browser = await self._browser("s1", talk=False)
        await _until(lambda: browser.frames["video"])

        assert "call-1" in self.line.ringing
        assert self._statuses() == ["SIP/2.0 180 Ringing"]
        assert self.talkback.video.running

    async def test_talking_answers_and_bridges_audio_both_ways(self) -> None:
        """Talk answers the ringing call; audio flows; closing hangs up."""
        await self._ring()

        browser = await self._browser("s1", talk=True)

        assert self._statuses()[-1] == "SIP/2.0 200 OK"
        assert not self.line.ringing
        await self._ack()
        call_audio = self.line.calls["call-1"].rtp_session()

        # Microphone -> call: the tone arrives in the RTP sent to the gateway.
        def sent_tone() -> bool:
            for data, _ in call_audio.transport.sent:
                pcm = g711_decode(RtpPacket.parse(data).payload, PCMA)
                if abs(int(np.median(pcm)) - TONE) < TONE * 0.1:
                    return True
            return False

        await _until(sent_tone)

        # Door station -> browser: received RTP plays out to the browser.
        door = g711_encode(np.full(SAMPLES_PER_FRAME, -TONE), PCMA)
        for seq in range(100):
            packet = RtpPacket(PCMA, seq, seq * SAMPLES_PER_FRAME, 99, door)
            call_audio.datagram_received(packet.serialize(), ("192.168.1.10", 4000))

        def heard_door() -> bool:
            return any(
                np.abs(frame.to_ndarray()).max() > TONE / 2
                for frame in browser.frames["audio"]
            )

        await _until(heard_door)

        await self.talkback.close_session("s1")

        assert self._requests(b"BYE ") == 1
        assert isinstance(self.events[-1], CallEnded)
        assert not self.talkback.video.running

    async def test_last_talking_session_hangs_up(self) -> None:
        """With two talkers, only closing the second one hangs up."""
        await self._ring()
        await self._browser("s1", talk=True)
        await self._ack()
        await self._browser("s2", talk=True)
        await self._browser("s3", talk=False)

        await self.talkback.close_session("s1")
        await self.talkback.close_session("s3")
        assert self._requests(b"BYE ") == 0

        await self.talkback.close_session("s2")
        assert self._requests(b"BYE ") == 1

    async def test_watching_an_auto_answered_call_never_hangs_up(self) -> None:
        """Calls nobody talked on keep running when viewers leave."""
        await self.talkback.close()
        await self.line.stop()
        self._setup(auto_answer=True)
        await self._ring()
        await self._ack()

        await self._browser("s1", talk=False)
        await self.talkback.close_session("s1")

        assert self._requests(b"BYE ") == 0
        assert "call-1" in self.line.calls

    async def test_candidates_wait_for_the_offer_and_unknown_sessions_fail(
        self,
    ) -> None:
        """End-of-candidates is accepted; unknown sessions raise."""
        await self._browser("s1", talk=False)

        await self.talkback.add_candidate("s1", "", "0", 0)
        with pytest.raises(ValueError, match="Unknown WebRTC session"):
            await self.talkback.add_candidate("nope", "", "0", 0)

    async def test_talking_without_a_call_answers_nothing(self) -> None:
        """Talking with no call ringing just opens the session."""
        await self._browser("s1", talk=True)

        await self.talkback.close_session("s1")

        assert self.transport.sent == []


if __name__ == "__main__":
    unittest.main()
