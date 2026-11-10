"""
Live talk-back for a door station camera, over WebRTC.

Talkback answers each WebRTC session of the camera with an aiortc peer
connection carrying the camera's video and the door station's audio. A session
whose offer sends audio (the frontend's talk button) talks: it answers the
door station's ringing call, its microphone goes into the call, and when the
last talking session closes the call is hung up.
"""

from __future__ import annotations

import asyncio
import contextlib
import fractions
import ipaddress
import re
import time
import warnings
from collections import Counter, deque
from typing import TYPE_CHECKING

import av
import ifaddr
import numpy as np
from homeassistant.components.camera import WebRTCAnswer, WebRTCError

from .const import LOGGER
from .line import (
    CallEnded,
    CallFailedError,
    CallStarted,
    IncomingCall,
    NotRingingError,
)
from .sip.rtp import PTIME, SAMPLE_RATE, SAMPLES_PER_FRAME

# aiortc only uses google-crc32c to checksum SCTP (data channel) packets, and the
# sessions here carry none but the frontend's unused channel.
# Suppress just that warning.
with warnings.catch_warnings():
    warnings.filterwarnings(
        "ignore",
        message=r".*(?:pure[- ]Python implementation|using a python implementation).*",
        category=RuntimeWarning,
        module=r"^google_crc32c(?:\..+)?$",
    )
    from aiortc import (
        RTCConfiguration,
        RTCIceServer,
        RTCPeerConnection,
        RTCRtpSender,
        RTCSessionDescription,
    )
    from aiortc.mediastreams import MediaStreamError, MediaStreamTrack
    from aiortc.sdp import candidate_from_sdp

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from aiortc import RTCRtpCodecCapability
    from homeassistant.components.camera import WebRTCSendMessage

    from .line import Call, GatewayLine, LineEvent
    from .sip.rtp import RtpSession

    type JpegSource = Callable[[], AsyncIterator[bytes]]

VIDEO_FPS = 15
# Closing a peer connection may hang on a dead network; give up after this.
CLOSE_TIMEOUT = 5.0
VIDEO_BITRATE = 800_000
VIDEO_TIME_BASE = fractions.Fraction(1, 90000)
# A keyframe every two seconds, so a viewer recovers quickly from packet loss.
KEYFRAME_INTERVAL = 2 * VIDEO_FPS
VIDEO_QUEUE = 30
# A failed camera stream is reopened after RECONNECT_DELAY, doubling up to
# MAX_RECONNECT_DELAY until a frame arrives again.
RECONNECT_DELAY = 2.0
MAX_RECONNECT_DELAY = 30.0
# Door audio frames a viewer may lag behind before the oldest are dropped.
AUDIO_QUEUE = 5
AUDIO_TIME_BASE = fractions.Fraction(1, SAMPLE_RATE)
# How long a candidate waits for its session's offer to be handled.
CANDIDATE_TIMEOUT = 10
# How long an offer waits for the browser's candidates to tell whether it is on
# our network. aiortc gathers every candidate before it answers, and a STUN
# query that gets no reply costs aioice's full 5 s, so a browser on the LAN is
# answered without ICE servers.
LAN_CANDIDATE_WAIT = 0.5

_OFFER_CANDIDATE = re.compile(r"^a=(candidate:.*|end-of-candidates)\s*$", re.MULTILINE)

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def lan_networks() -> list[Network]:
    """Return the networks of our interfaces, without link-local ones."""
    networks = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            address = ip.ip if isinstance(ip.ip, str) else ip.ip[0]
            try:
                network = ipaddress.ip_interface(
                    f"{address}/{ip.network_prefix}"
                ).network
            except ValueError:
                continue
            # Every network has link-local addresses, so they say nothing.
            if not network.is_link_local:
                networks.append(network)
    return networks


def browser_on_lan(candidates: list[str], networks: list[Network]) -> bool | None:
    """
    Tell from a browser's ICE candidates whether it shares a network with us.

    True once a host candidate is on one of `networks`. False once a server
    reflexive or relayed candidate, or the end of candidates, arrived without
    one, as browsers announce their host candidates first. None while
    undecided. Hidden (mDNS) host addresses never match.
    """
    for value in candidates:
        parts = value.removeprefix("candidate:").split()
        if not parts or parts[0] == "end-of-candidates":
            continue
        try:
            kind = parts[parts.index("typ") + 1]
            address = ipaddress.ip_address(parts[4])
        except (ValueError, IndexError):
            continue  # an mDNS name, or not a candidate
        if kind == "host" and any(address in network for network in networks):
            return True
    if any(
        not value.strip()
        or value == "end-of-candidates"
        or re.search(r"\btyp (srflx|relay)\b", value)
        for value in candidates
    ):
        return False
    return None


def offer_sends_audio(offer_sdp: str) -> bool:
    """Return whether an SDP offer sends audio, i.e. the viewer wants to talk."""
    sends = False
    in_audio = False
    for raw in offer_sdp.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            parts = line.split()
            in_audio = parts[0] == "m=audio" and len(parts) > 1 and parts[1] != "0"
            if in_audio:
                sends = True  # sendrecv is the default direction
        elif in_audio and line in {"a=recvonly", "a=inactive"}:
            sends = False
    return sends


def _codecs(kind: str, mime_types: list[str]) -> list[RTCRtpCodecCapability]:
    capabilities = RTCRtpSender.getCapabilities(kind).codecs
    return [
        codec
        for mime_type in mime_types
        for codec in capabilities
        if codec.mimeType.lower() == mime_type.lower()
    ]


# ============================================================
# Video
# ============================================================


class EncodedVideoTrack(MediaStreamTrack):
    """One viewer's copy of the shared VP8 stream, as pre-encoded packets."""

    kind = "video"

    def __init__(self, source: VideoSource) -> None:
        """Create a track fed by `source`."""
        super().__init__()
        self._source = source
        self._queue: asyncio.Queue[av.Packet] = asyncio.Queue(VIDEO_QUEUE)
        self._needs_keyframe = True

    def put(self, packet: av.Packet) -> None:
        """Queue an encoded packet, starting at a keyframe."""
        if self._needs_keyframe and not packet.is_keyframe:
            return
        if self._queue.full():
            # The viewer fell behind: drop what it has and resync on a keyframe.
            while not self._queue.empty():
                self._queue.get_nowait()
            self._needs_keyframe = True
            self._source.request_keyframe()
            return
        self._needs_keyframe = False
        self._queue.put_nowait(packet)

    async def recv(self) -> av.Packet:
        """Return the next encoded packet."""
        if self.readyState != "live":
            raise MediaStreamError
        return await self._queue.get()

    def stop(self) -> None:
        """Stop the track and leave the shared stream."""
        super().stop()
        self._source.remove(self)


class VideoSource:
    """
    The camera's MJPEG frames, decoded and encoded to VP8 once for all viewers.

    It runs only while at least one track exists.
    """

    def __init__(self, jpegs: JpegSource) -> None:
        """Create a source reading JPEG frames from `jpegs`."""
        self._jpegs = jpegs
        self._tracks: set[EncodedVideoTrack] = set()
        self._task: asyncio.Task | None = None
        self._decoder: av.CodecContext | None = None
        self._encoder: av.VideoCodecContext | None = None
        self._keyframe = True
        self._started = 0.0

    @property
    def running(self) -> bool:
        """Return whether frames are being read and encoded."""
        return self._task is not None

    def track(self) -> EncodedVideoTrack:
        """Return a new track of the stream, starting the source if needed."""
        track = EncodedVideoTrack(self)
        self._tracks.add(track)
        self.request_keyframe()
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="sg150-video")
        return track

    def remove(self, track: EncodedVideoTrack) -> None:
        """Remove a track, stopping the source after the last one."""
        self._tracks.discard(track)
        if not self._tracks and self._task is not None:
            self._task.cancel()
            self._task = None

    def request_keyframe(self) -> None:
        """Make the next encoded frame a keyframe."""
        self._keyframe = True

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        self._decoder = self._encoder = None
        self._started = time.monotonic()
        last_frame = -1.0
        delay, warned = RECONNECT_DELAY, False
        while True:
            try:
                async for jpeg in self._jpegs():
                    delay, warned = RECONNECT_DELAY, False
                    now = time.monotonic()
                    if now - last_frame < 1 / VIDEO_FPS:
                        continue
                    last_frame = now
                    pts = int((now - self._started) / VIDEO_TIME_BASE)
                    packets = await loop.run_in_executor(None, self._encode, jpeg, pts)
                    for packet in packets:
                        for track in list(self._tracks):
                            track.put(packet)
            except Exception as err:  # noqa: BLE001
                if warned:
                    LOGGER.debug("Camera video stream failed", exc_info=True)
                else:
                    warned = True
                    LOGGER.warning("Camera video stream failed, retrying: %r", err)
            await asyncio.sleep(delay)
            delay = min(delay * 2, MAX_RECONNECT_DELAY)

    def _encode(self, jpeg: bytes, pts: int) -> list[av.Packet]:
        """Decode a JPEG and encode it to VP8; runs in an executor thread."""
        if self._decoder is None:
            self._decoder = av.CodecContext.create("mjpeg", "r")
        try:
            frames = self._decoder.decode(av.Packet(jpeg))
        except av.error.FFmpegError:
            return []

        packets: list[av.Packet] = []
        for decoded in frames:
            frame = decoded.reformat(format="yuv420p")
            if self._encoder is None or (frame.width, frame.height) != (
                self._encoder.width,
                self._encoder.height,
            ):
                self._encoder = self._create_encoder(frame.width, frame.height)
                self._keyframe = True
            frame.pts = pts
            frame.time_base = VIDEO_TIME_BASE
            if self._keyframe:
                frame.pict_type = av.video.frame.PictureType.I
                self._keyframe = False
            for packet in self._encoder.encode(frame):
                packet.time_base = VIDEO_TIME_BASE
                packets.append(packet)
        return packets

    @staticmethod
    def _create_encoder(width: int, height: int) -> av.VideoCodecContext:
        """Create a real-time VP8 encoder, configured like aiortc's own."""
        encoder = av.CodecContext.create("libvpx", "w")
        encoder.width = width
        encoder.height = height
        encoder.bit_rate = VIDEO_BITRATE
        encoder.pix_fmt = "yuv420p"
        encoder.time_base = VIDEO_TIME_BASE
        encoder.framerate = fractions.Fraction(VIDEO_FPS)
        encoder.gop_size = KEYFRAME_INTERVAL
        encoder.qmin = 2
        encoder.qmax = 56
        encoder.options = {
            "bufsize": str(VIDEO_BITRATE),
            "cpu-used": "-6",
            "deadline": "realtime",
            "lag-in-frames": "0",
            "minrate": str(VIDEO_BITRATE),
            "maxrate": str(VIDEO_BITRATE),
            "noise-sensitivity": "4",
            "overshoot-pct": "15",
            "partitions": "0",
            "static-thresh": "1",
            "undershoot-pct": "100",
        }
        return encoder


# ============================================================
# Audio
# ============================================================


class DoorAudioTrack(MediaStreamTrack):
    """The door station's audio for one viewer, 20 ms frames, silence by default."""

    kind = "audio"

    def __init__(self) -> None:
        """Create a silent track."""
        super().__init__()
        self._frames: deque[np.ndarray] = deque(maxlen=AUDIO_QUEUE)
        self._start: float | None = None
        self._timestamp = 0

    def put(self, pcm: np.ndarray) -> None:
        """Queue a 20 ms frame of 8 kHz int16 audio from the call."""
        self._frames.append(pcm)

    async def recv(self) -> av.AudioFrame:
        """Return the next 20 ms frame, paced in real time."""
        if self.readyState != "live":
            raise MediaStreamError
        if self._start is None:
            self._start = time.monotonic()
        else:
            self._timestamp += SAMPLES_PER_FRAME
            wait = self._start + self._timestamp / SAMPLE_RATE - time.monotonic()
            if wait < -5 * PTIME:
                # Fell far behind, such as after the event loop stalled.
                self._start = time.monotonic() - self._timestamp / SAMPLE_RATE
            await asyncio.sleep(max(0.0, wait))

        pcm = (
            self._frames.popleft()
            if self._frames
            else np.zeros(SAMPLES_PER_FRAME, dtype=np.int16)
        )
        frame = av.AudioFrame.from_ndarray(
            pcm.reshape(1, -1), format="s16", layout="mono"
        )
        frame.sample_rate = SAMPLE_RATE
        frame.pts = self._timestamp
        frame.time_base = AUDIO_TIME_BASE
        return frame


# ============================================================
# Sessions
# ============================================================


class _Session:
    """One WebRTC session of the camera."""

    def __init__(
        self, session_id: str, *, talking: bool, video: EncodedVideoTrack
    ) -> None:
        self.id = session_id
        self.talking = talking
        self.pc: RTCPeerConnection | None = None
        self.audio = DoorAudioTrack()
        self.video = video
        self.ready = asyncio.Event()
        self.tasks: set[asyncio.Task] = set()
        # The browser's ICE candidates that arrived before our answer.
        self.browser_candidates: list[str] = []
        self.candidate_added = asyncio.Event()
        self.started = time.monotonic()

    async def close(self) -> None:
        for task in self.tasks:
            task.cancel()
        self.audio.stop()
        self.video.stop()
        self.ready.set()
        if self.pc is not None:
            await self.pc.close()


class Talkback:
    """WebRTC sessions of one door station camera, bridged to its SIP calls."""

    def __init__(self, line: GatewayLine, device_id: str, jpegs: JpegSource) -> None:
        """
        Create a bridge for the door station `device_id` on `line`.

        jpegs: opens the camera's MJPEG stream and yields its JPEG frames.
        """
        self._line = line
        self._device_id = device_id
        self._video = VideoSource(jpegs)
        self._sessions: dict[str, _Session] = {}
        # Ids of talking sessions in the order they started talking; the last
        # one's microphone goes into the call.
        self._talkers: list[str] = []
        self._call: Call | None = None
        self._call_audio: RtpSession | None = None
        self._unsubscribe_call_audio: Callable[[], None] | None = None
        # Whether a session talked during the current call, so closing the last
        # talking session hangs it up. Calls nobody talked on are left alone.
        self._talked = False
        # Tasks answering a ring for an open microphone, cancelled by close().
        self._tasks: set[asyncio.Task] = set()
        self._unsubscribe_line = line.subscribe(self._on_line_event)
        self._attach_to_a_call()

    @property
    def video(self) -> VideoSource:
        """Return the shared video source."""
        return self._video

    # Calls

    def _on_line_event(self, event: LineEvent) -> None:
        if isinstance(event, CallStarted) and event.call.involves(self._device_id):
            if self._call is None:
                self._attach(event.call)
        elif (
            isinstance(event, CallEnded)
            and self._call is not None
            and event.call.id == self._call.id
        ):
            self._detach()
            # A second call with this door may still be running.
            self._attach_to_a_call(skip=event.call.id)
        elif (
            isinstance(event, IncomingCall)
            and not event.answered
            and self._talkers
            and event.call.involves(self._device_id)
        ):
            # An open microphone answers the ring, like pressing talk would.
            task = asyncio.create_task(
                self._answer_ringing_call(), name=f"talkback-answer-{event.call.id}"
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    def _attach_to_a_call(self, skip: str | None = None) -> None:
        for call in self._line.calls.values():
            if call.id != skip and call.involves(self._device_id):
                self._attach(call)
                return

    def _attach(self, call: Call) -> None:
        try:
            self._call_audio = call.rtp_session()
        except ValueError:
            return
        self._call = call
        self._talked = bool(self._talkers)
        self._unsubscribe_call_audio = self._call_audio.subscribe(self._on_door_audio)

    def _detach(self) -> None:
        if self._unsubscribe_call_audio is not None:
            self._unsubscribe_call_audio()
        self._unsubscribe_call_audio = None
        self._call = self._call_audio = None
        self._talked = False

    def _on_door_audio(self, pcm: np.ndarray) -> None:
        for session in self._sessions.values():
            session.audio.put(pcm)

    async def _answer_ringing_call(self) -> None:
        for call in list(self._line.ringing.values()):
            if call.involves(self._device_id):
                try:
                    with contextlib.suppress(NotRingingError):  # answered already
                        await self._line.answer(call.id)
                except CallFailedError as err:
                    LOGGER.warning("Could not answer the ring: %s", err)
                return

    async def _read_microphone(
        self, session: _Session, track: MediaStreamTrack
    ) -> None:
        resampler = av.AudioResampler(format="s16", layout="mono", rate=SAMPLE_RATE)
        while True:
            try:
                frame = await track.recv()
            except MediaStreamError:
                return
            if self._talkers[-1:] != [session.id] or self._call_audio is None:
                continue
            for resampled in resampler.resample(frame):
                self._call_audio.write_pcm(
                    resampled.to_ndarray().reshape(-1), live=True
                )

    # WebRTC

    async def handle_offer(
        self,
        session_id: str,
        offer_sdp: str,
        send_message: WebRTCSendMessage,
        ice_servers: list[RTCIceServer],
    ) -> None:
        """Answer a WebRTC offer; a talking offer also answers a ringing call."""
        session = _Session(
            session_id, talking=offer_sends_audio(offer_sdp), video=self._video.track()
        )
        self._sessions[session_id] = session
        try:
            on_lan = bool(ice_servers) and await self._browser_on_lan(
                session, offer_sdp
            )
            pc = session.pc = RTCPeerConnection(
                RTCConfiguration(iceServers=[] if on_lan else ice_servers)
            )

            audio = pc.addTransceiver(
                session.audio, direction="sendrecv" if session.talking else "sendonly"
            )
            audio.setCodecPreferences(
                _codecs("audio", ["audio/PCMA", "audio/PCMU", "audio/opus"])
            )
            video = pc.addTransceiver(session.video, direction="sendonly")
            video.setCodecPreferences(_codecs("video", ["video/VP8"]))

            @pc.on("track")
            def on_track(track: MediaStreamTrack) -> None:
                if track.kind == "audio" and session.talking:
                    task = asyncio.create_task(self._read_microphone(session, track))
                    session.tasks.add(task)
                    task.add_done_callback(session.tasks.discard)

            @pc.on("connectionstatechange")
            async def on_connection_state_change() -> None:
                if pc.connectionState == "connected":
                    LOGGER.debug(
                        "WebRTC session %s connected %.2f s after its offer",
                        session_id,
                        time.monotonic() - session.started,
                    )
                if pc.connectionState == "failed" and session_id in self._sessions:
                    send_message(
                        WebRTCError("webrtc_failed", "The WebRTC connection failed")
                    )
                    await self.close_session(session_id)

            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=offer_sdp, type="offer")
            )
            await pc.setLocalDescription(await pc.createAnswer())
        except Exception:
            await self.close_session(session_id)
            raise
        if self._sessions.get(session_id) is not session:
            return  # closed while the answer was being created
        session.ready.set()
        send_message(WebRTCAnswer(pc.localDescription.sdp))
        LOGGER.debug(
            "WebRTC session %s for %s answered in %.2f s (talking: %s, "
            "browser on LAN: %s, our candidates: %s)",
            session_id,
            self._device_id,
            time.monotonic() - session.started,
            session.talking,
            on_lan,
            dict(Counter(re.findall(r" typ (\w+)", pc.localDescription.sdp))),
        )

        if session.talking:
            self._talkers.append(session_id)
            if self._call is not None:
                self._talked = True
            await self._answer_ringing_call()

    async def _browser_on_lan(self, session: _Session, offer_sdp: str) -> bool:
        """Wait up to LAN_CANDIDATE_WAIT for the browser's candidates to tell."""
        networks = await asyncio.to_thread(lan_networks)
        offered = _OFFER_CANDIDATE.findall(offer_sdp)
        deadline = time.monotonic() + LAN_CANDIDATE_WAIT
        while (
            verdict := browser_on_lan([*offered, *session.browser_candidates], networks)
        ) is None:
            session.candidate_added.clear()
            try:
                await asyncio.wait_for(
                    session.candidate_added.wait(), deadline - time.monotonic()
                )
            except TimeoutError:
                return False
        return verdict

    async def add_candidate(
        self,
        session_id: str,
        candidate: str,
        sdp_mid: str | None,
        sdp_m_line_index: int | None,
    ) -> None:
        """Add a remote ICE candidate, once the session's offer is handled."""
        session = self._sessions.get(session_id)
        if session is None:
            msg = f"Unknown WebRTC session: {session_id}"
            raise ValueError(msg)
        if not session.ready.is_set():
            # Tells _browser_on_lan whether the browser is on our network.
            session.browser_candidates.append(candidate)
            session.candidate_added.set()
        await asyncio.wait_for(session.ready.wait(), CANDIDATE_TIMEOUT)
        value = candidate.removeprefix("candidate:").strip()
        if not value or self._sessions.get(session_id) is not session:
            return  # end of candidates, or the session closed
        ice_candidate = candidate_from_sdp(value)
        ice_candidate.sdpMid = sdp_mid
        ice_candidate.sdpMLineIndex = sdp_m_line_index
        await session.pc.addIceCandidate(ice_candidate)

    async def close_session(self, session_id: str) -> None:
        """Close a session; hang up if it was the last one talking on a call."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        was_talking = session_id in self._talkers
        if was_talking:
            self._talkers.remove(session_id)
        try:
            # Hang up first, so a peer connection that fails to close can't
            # keep the door line open.
            if (
                was_talking
                and not self._talkers
                and self._talked
                and (call := self._call) is not None
            ):
                LOGGER.debug("Last talking session closed, hanging up %s", call.id)
                with contextlib.suppress(ValueError):  # it ended meanwhile
                    await call.hangup()
        finally:
            try:
                await asyncio.wait_for(session.close(), CLOSE_TIMEOUT)
            except TimeoutError:
                LOGGER.warning("Closing WebRTC session %s timed out", session_id)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Error closing WebRTC session %s", session_id)

    async def close(self) -> None:
        """Close all sessions without hanging up, such as on unload."""
        self._unsubscribe_line()
        for task in self._tasks:
            task.cancel()
        self._detach()
        self._talkers.clear()
        for session_id in list(self._sessions):
            await self.close_session(session_id)
