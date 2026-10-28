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
import time
from collections import deque
from typing import TYPE_CHECKING

import av
import numpy as np
from aiortc import (
    RTCConfiguration,
    RTCPeerConnection,
    RTCRtpSender,
    RTCSessionDescription,
)
from aiortc.mediastreams import MediaStreamError, MediaStreamTrack
from aiortc.sdp import candidate_from_sdp
from homeassistant.components.camera import WebRTCAnswer, WebRTCError

from .const import LOGGER
from .line import CallEnded, CallStarted, NotRingingError
from .sip.rtp import PTIME, SAMPLE_RATE, SAMPLES_PER_FRAME

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from aiortc import RTCIceServer, RTCRtpCodecCapability
    from homeassistant.components.camera import WebRTCSendMessage

    from .line import Call, GatewayLine, LineEvent
    from .sip.rtp import RtpSession

    type JpegSource = Callable[[], AsyncIterator[bytes]]

VIDEO_FPS = 15
VIDEO_BITRATE = 800_000
VIDEO_TIME_BASE = fractions.Fraction(1, 90000)
# A keyframe every two seconds, so a viewer recovers quickly from packet loss.
KEYFRAME_INTERVAL = 2 * VIDEO_FPS
VIDEO_QUEUE = 30
RECONNECT_DELAY = 2.0
# Door audio frames a viewer may lag behind before the oldest are dropped.
AUDIO_QUEUE = 5
AUDIO_TIME_BASE = fractions.Fraction(1, SAMPLE_RATE)
# How long a candidate waits for its session's offer to be handled.
CANDIDATE_TIMEOUT = 10


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
        while True:
            try:
                async for jpeg in self._jpegs():
                    now = time.monotonic()
                    if now - last_frame < 1 / VIDEO_FPS:
                        continue
                    last_frame = now
                    pts = int((now - self._started) / VIDEO_TIME_BASE)
                    packets = await loop.run_in_executor(None, self._encode, jpeg, pts)
                    for packet in packets:
                        for track in list(self._tracks):
                            track.put(packet)
            except Exception:  # noqa: BLE001
                LOGGER.debug("Camera video stream failed", exc_info=True)
            await asyncio.sleep(RECONNECT_DELAY)

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
        self._unsubscribe_line = line.subscribe(self._on_line_event)
        for call in line.calls.values():
            if call.involves(device_id):
                self._attach(call)
                break

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
                with contextlib.suppress(NotRingingError):
                    await self._line.answer(call.id)
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
        pc = session.pc = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers))

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
            if pc.connectionState == "failed" and session_id in self._sessions:
                send_message(
                    WebRTCError("webrtc_failed", "The WebRTC connection failed")
                )
                await self.close_session(session_id)

        try:
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
            "WebRTC session %s started for %s (talking: %s)",
            session_id,
            self._device_id,
            session.talking,
        )

        if session.talking:
            self._talkers.append(session_id)
            if self._call is not None:
                self._talked = True
            await self._answer_ringing_call()

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
        await session.close()
        if session_id not in self._talkers:
            return
        self._talkers.remove(session_id)
        if not self._talkers and self._talked and (call := self._call) is not None:
            LOGGER.debug("Last talking session closed, hanging up %s", call.id)
            with contextlib.suppress(ValueError):  # it ended meanwhile
                await call.hangup()

    async def close(self) -> None:
        """Close all sessions without hanging up, such as on unload."""
        self._unsubscribe_line()
        self._detach()
        self._talkers.clear()
        for session_id in list(self._sessions):
            await self.close_session(session_id)
