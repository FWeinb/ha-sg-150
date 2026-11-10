"""
Tests for Talkback, with an in-process aiortc peer as the browser.

The browser offers like the Home Assistant frontend: a recvonly audio
transceiver to watch, a sendrecv one with a microphone to talk, and a recvonly
video transceiver. The SIP side is a MiniSIPServer on fake transports.
"""

import asyncio
import fractions
import ipaddress
import socket
import time
import unittest
from collections.abc import AsyncIterator
from unittest.mock import patch

import av
import numpy as np
import pytest
from aioice import Candidate, Connection
from aiortc import (
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.mediastreams import MediaStreamError, MediaStreamTrack
from homeassistant.components.camera import WebRTCAnswer, WebRTCMessage

from custom_components.sg_150 import talkback
from custom_components.sg_150.line import CallEnded, GatewayLine, LineEvent
from custom_components.sg_150.sip.minisip import MiniSIPServer
from custom_components.sg_150.sip.rtp import (
    PCMA,
    SAMPLES_PER_FRAME,
    RtpPacket,
    g711_decode,
    g711_encode,
)
from custom_components.sg_150.talkback import (
    Talkback,
    browser_on_lan,
    lan_networks,
    offer_sends_audio,
)
from tests.sip_messages import (
    GATEWAY,
    HA_HOST,
    HA_NUMBER,
    SIP_PASSWORD,
    SIP_USER,
    ack,
    bye,
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

    async def connect(
        self,
        talkback: Talkback,
        session_id: str,
        ice_servers: list[RTCIceServer] | None = None,
    ) -> str:
        """Send our offer to `talkback` and apply its answer; return the offer."""
        await self.pc.setLocalDescription(await self.pc.createOffer())
        messages: list[WebRTCMessage] = []
        offer = self.pc.localDescription.sdp
        await talkback.handle_offer(
            session_id, offer, messages.append, ice_servers or []
        )
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


LAN = [ipaddress.ip_network("192.168.1.0/24"), ipaddress.ip_network("2001:db8:1::/64")]
# A STUN server that never answers (TEST-NET-1).
SILENT_STUN = [RTCIceServer(urls="stun:192.0.2.1:3478")]


def _candidate(address: str, kind: str = "host") -> str:
    return f"candidate:1 1 udp 2122260223 {address} 50000 typ {kind}"


class LanTests(unittest.TestCase):
    """Telling from a browser's candidates whether it is on our network."""

    def test_host_candidate_on_our_network_is_lan(self) -> None:
        """An IPv4 or IPv6 host address in one of our networks decides it."""
        assert browser_on_lan([_candidate("10.0.0.5"), _candidate("192.168.1.7")], LAN)
        assert browser_on_lan([_candidate("2001:db8:1::42")], LAN)

    def test_reflexive_candidate_or_end_without_a_match_is_remote(self) -> None:
        """Host candidates come first, so a later srflx or the end decides."""
        assert browser_on_lan([_candidate("10.0.0.5")], LAN) is None
        assert browser_on_lan([_candidate("203.0.113.9", "srflx")], LAN) is False
        assert browser_on_lan([_candidate("abc.local"), ""], LAN) is False
        assert browser_on_lan(["end-of-candidates"], LAN) is False

    def test_hidden_or_malformed_candidates_decide_nothing(self) -> None:
        """Hidden mDNS names and garbage neither match nor end the wait."""
        assert browser_on_lan([_candidate("0b1f.local"), "candidate:x"], LAN) is None
        assert browser_on_lan([], LAN) is None

    def test_link_local_networks_are_left_out(self) -> None:
        """Every network has link-local addresses, so they can't tell."""
        ip = type("IP", (), {})

        def address(value: object, prefix: int) -> object:
            result = ip()
            result.ip, result.network_prefix = value, prefix
            return result

        adapter = type("Adapter", (), {})()
        adapter.ips = [
            address("192.168.1.2", 24),
            address("169.254.3.4", 16),
            address(("fe80::1", 0, 4), 64),
            address(("2001:db8:1::2", 0, 0), 64),
        ]
        with patch("ifaddr.get_adapters", return_value=[adapter]):
            assert lan_networks() == LAN


@pytest.mark.usefixtures("socket_enabled")
class IceCloseTests(unittest.IsolatedAsyncioTestCase):
    """Closing an ICE connection while its checks still run."""

    async def test_close_while_trickling_drops_stun_retransmissions(self) -> None:
        """Checks outliving their closed sockets don't crash the event loop."""
        errors: list[dict] = []
        asyncio.get_running_loop().set_exception_handler(
            lambda _, context: errors.append(context)
        )
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(silent.close)
        silent.bind(("127.0.0.1", 0))
        with patch("aioice.ice.get_host_addresses", return_value=["127.0.0.1"]):
            connection = Connection(ice_controlling=True)
            await connection.gather_candidates()
        connection.remote_username, connection.remote_password = "abcd", "a" * 22
        port = silent.getsockname()[1]
        await connection.add_remote_candidate(
            Candidate("1", 1, "udp", 100, "127.0.0.1", port, "host")
        )
        # No end-of-candidates: the browser is still trickling.
        connect = asyncio.create_task(connection.connect())
        await asyncio.sleep(0.1)

        await connection.close()
        await asyncio.sleep(0.6)  # past the first STUN retransmission
        connect.cancel()

        assert errors == []


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
            trusted_hosts=[GATEWAY[0]],
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

    async def test_lan_browser_is_answered_without_ice_servers(self) -> None:
        """A browser on our network doesn't wait for STUN, and still connects."""
        browser = Browser(talk=False)
        self.browsers.append(browser)
        with (
            patch.object(
                talkback,
                "lan_networks",
                return_value=[ipaddress.ip_network("127.0.0.0/8")],
            ),
            patch.object(
                talkback, "RTCConfiguration", wraps=talkback.RTCConfiguration
            ) as configuration,
        ):
            await browser.connect(self.talkback, "s1", SILENT_STUN)

        assert configuration.call_args.kwargs["iceServers"] == []
        await _until(lambda: browser.frames["video"])

    async def test_remote_browser_keeps_the_ice_servers(self) -> None:
        """A browser elsewhere is answered with the configured servers."""
        browser = Browser(talk=False)
        self.browsers.append(browser)
        with (
            patch.object(talkback, "lan_networks", return_value=[]),
            # Fail the STUN query at once instead of after aioice's 5 s.
            patch("aioice.ice.server_reflexive_candidate", side_effect=OSError),
            patch.object(
                talkback, "RTCConfiguration", wraps=talkback.RTCConfiguration
            ) as configuration,
        ):
            await browser.connect(self.talkback, "s1", SILENT_STUN)

        assert configuration.call_args.kwargs["iceServers"] == SILENT_STUN

    async def _decide(self, offer: str = "v=0\r\n") -> asyncio.Task[bool]:
        session = talkback._Session(  # noqa: SLF001
            "s1", talking=True, video=self.talkback.video.track()
        )
        self.talkback._sessions["s1"] = session  # noqa: SLF001
        decide = asyncio.create_task(
            self.talkback._browser_on_lan(session, offer)  # noqa: SLF001
        )
        await asyncio.sleep(0.01)
        return decide

    async def test_trickled_lan_candidate_answers_early(self) -> None:
        """A LAN candidate arriving after the offer ends the wait at once."""
        with patch.object(talkback, "lan_networks", return_value=LAN):
            decide = await self._decide()
            started = time.monotonic()
            add = asyncio.create_task(
                self.talkback.add_candidate("s1", _candidate("192.168.1.7"), "0", 0)
            )

            assert await decide is True
        assert time.monotonic() - started < talkback.LAN_CANDIDATE_WAIT
        add.cancel()

    async def test_undecided_browser_falls_back_to_the_servers(self) -> None:
        """Without a deciding candidate the offer waits only briefly."""
        with (
            patch.object(talkback, "lan_networks", return_value=LAN),
            patch.object(talkback, "LAN_CANDIDATE_WAIT", 0.05),
        ):
            decide = await self._decide()

            assert await decide is False

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

    async def test_failing_peer_connection_close_still_hangs_up(self) -> None:
        """Hanging up comes first, so a failing pc.close() cannot skip it."""
        await self._ring()
        await self._browser("s1", talk=True)
        await self._ack()

        session = self.talkback._sessions["s1"]  # noqa: SLF001
        with (
            patch.object(session.pc, "close", side_effect=RuntimeError("boom")),
            self.assertLogs("custom_components.sg_150", "ERROR"),
        ):
            await self.talkback.close_session("s1")

        assert self._requests(b"BYE ") == 1
        assert isinstance(self.events[-1], CallEnded)

    async def test_hanging_peer_connection_close_times_out(self) -> None:
        """A pc.close() that never returns is given up after CLOSE_TIMEOUT."""
        await self._ring()
        await self._browser("s1", talk=True)
        await self._ack()

        session = self.talkback._sessions["s1"]  # noqa: SLF001
        never = asyncio.Event()
        with (
            patch.object(talkback, "CLOSE_TIMEOUT", 0.05),
            patch.object(session.pc, "close", side_effect=never.wait),
        ):
            await self.talkback.close_session("s1")

        assert self._requests(b"BYE ") == 1

    async def test_failed_offer_setup_closes_the_session(self) -> None:
        """An error while setting up the peer connection leaks no session."""
        with (
            patch.object(
                talkback.RTCPeerConnection,
                "addTransceiver",
                side_effect=RuntimeError("boom"),
            ),
            pytest.raises(RuntimeError),
        ):
            await self.talkback.handle_offer("s1", "v=0", lambda _: None, [])

        assert not self.talkback._sessions  # noqa: SLF001
        assert not self.talkback.video.running

    async def test_open_microphone_answers_a_new_ring(self) -> None:
        """A talking session opened before the ring answers it."""
        await self._browser("s1", talk=True)

        await self._ring()
        await _until(lambda: "SIP/2.0 200 OK" in self._statuses())
        await self._ack()

        assert not self.line.ringing
        await self.talkback.close_session("s1")
        assert self._requests(b"BYE ") == 1

    async def test_second_call_is_attached_after_the_first_ends(self) -> None:
        """When the first call with the door ends, a second one is bridged."""
        await self.talkback.close()
        await self.line.stop()
        self._setup(auto_answer=True)
        await self._ring("call-1")
        await self._ack("call-1")
        await self._ring("call-2")
        await self._ack("call-2")
        assert self.talkback._call.id == "call-1"  # noqa: SLF001

        await self.server.handle_datagram(bye("call-1"), GATEWAY)

        assert self.talkback._call.id == "call-2"  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
