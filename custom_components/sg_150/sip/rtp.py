"""
RTP media for MiniSIP calls.

One RtpSession per call owns the UDP socket on the port advertised in the SDP.
It sends a continuous 20 ms stream of G.711 (silence when nothing is queued),
and plays received audio out through a small fixed jitter buffer.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger("sip-server")

PCMU = 0
PCMA = 8
CODEC_NAMES = {PCMU: "PCMU", PCMA: "PCMA"}
SAMPLE_RATE = 8000
PTIME = 0.02
SAMPLES_PER_FRAME = int(SAMPLE_RATE * PTIME)
RTP_HEADER_SIZE = 12
RTP_VERSION = 2

# Live audio (a microphone) is dropped beyond this backlog, so a slow consumer
# can never build up more than this much delay. Queued clips are not limited.
MAX_LIVE_BACKLOG = 10
_SILENT_FRAME = np.zeros(SAMPLES_PER_FRAME, dtype=np.int16)
# Ticks this far behind schedule are skipped instead of sent in a burst.
MAX_TICK_LAG = 5


# ============================================================
# G.711
# ============================================================


def _alaw_encode_table() -> np.ndarray:
    """Build the A-law code for every int16 value (ITU-T G.711, Sun g711.c)."""
    pcm = np.arange(-32768, 32768, dtype=np.int32) >> 3
    mask = np.where(pcm >= 0, 0xD5, 0x55)
    pcm = np.where(pcm >= 0, pcm, -pcm - 1)
    seg = np.searchsorted(
        np.array([0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF]), pcm
    )
    quant = np.where(seg < 2, pcm >> 1, pcm >> np.maximum(seg, 1)) & 0xF  # noqa: PLR2004
    aval = np.where(seg >= 8, 0x7F, (seg << 4) | quant)  # noqa: PLR2004
    return (aval ^ mask).astype(np.uint8)


def _alaw_decode_table() -> np.ndarray:
    """Build the linear value of every A-law code."""
    code = np.arange(256, dtype=np.int32) ^ 0x55
    seg = (code & 0x70) >> 4
    t = (code & 0x0F) << 4
    t = np.where(seg == 0, t + 8, t + 0x108)
    t = np.where(seg > 1, t << np.maximum(seg - 1, 0), t)
    return np.where(code & 0x80, t, -t).astype(np.int16)


def _ulaw_encode_table() -> np.ndarray:
    """Build the µ-law code for every int16 value (ITU-T G.711, Sun g711.c)."""
    pcm = np.arange(-32768, 32768, dtype=np.int32) >> 2
    mask = np.where(pcm < 0, 0x7F, 0xFF)
    pcm = np.minimum(np.abs(pcm), 8159) + (0x84 >> 2)
    seg = np.searchsorted(
        np.array([0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF]), pcm
    )
    uval = np.where(seg >= 8, 0x7F, (seg << 4) | ((pcm >> (seg + 1)) & 0xF))  # noqa: PLR2004
    return (uval ^ mask).astype(np.uint8)


def _ulaw_decode_table() -> np.ndarray:
    """Build the linear value of every µ-law code."""
    code = ~np.arange(256, dtype=np.int32) & 0xFF
    t = (((code & 0x0F) << 3) + 0x84) << ((code & 0x70) >> 4)
    return np.where(code & 0x80, 0x84 - t, t - 0x84).astype(np.int16)


_ENCODE = {PCMA: _alaw_encode_table(), PCMU: _ulaw_encode_table()}
_DECODE = {PCMA: _alaw_decode_table(), PCMU: _ulaw_decode_table()}


def g711_encode(pcm: np.ndarray, payload_type: int) -> bytes:
    """Encode int16 PCM samples as PCMA or PCMU."""
    samples = np.asarray(pcm, dtype=np.int16).astype(np.int32) + 32768
    return _ENCODE[payload_type][samples].tobytes()


def g711_decode(payload: bytes, payload_type: int) -> np.ndarray:
    """Decode a PCMA or PCMU payload to int16 PCM samples."""
    return _DECODE[payload_type][np.frombuffer(payload, dtype=np.uint8)]


# ============================================================
# Packets and jitter buffer
# ============================================================


def seq_diff(a: int, b: int) -> int:
    """Return a - b for 16-bit sequence numbers, allowing for wrap-around."""
    return ((a - b + 0x8000) & 0xFFFF) - 0x8000


@dataclass(frozen=True)
class RtpPacket:
    """An RTP packet (RFC 3550) without CSRCs or header extensions."""

    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes
    marker: bool = False

    def serialize(self) -> bytes:
        """Return the packet as bytes."""
        header = bytes(
            [
                RTP_VERSION << 6,
                (0x80 if self.marker else 0) | (self.payload_type & 0x7F),
            ]
        )
        return (
            header
            + self.sequence.to_bytes(2, "big")
            + self.timestamp.to_bytes(4, "big")
            + self.ssrc.to_bytes(4, "big")
            + self.payload
        )

    @classmethod
    def parse(cls, data: bytes) -> RtpPacket | None:
        """Parse an RTP packet, or return None if it is not one."""
        if len(data) < RTP_HEADER_SIZE or data[0] >> 6 != RTP_VERSION:
            return None
        offset = RTP_HEADER_SIZE + 4 * (data[0] & 0x0F)
        if data[0] & 0x10:  # header extension
            if len(data) < offset + 4:
                return None
            offset += 4 + 4 * int.from_bytes(data[offset + 2 : offset + 4], "big")
        end = len(data)
        if data[0] & 0x20:  # padding
            end -= data[-1]
        if offset > end:
            return None
        return cls(
            payload_type=data[1] & 0x7F,
            sequence=int.from_bytes(data[2:4], "big"),
            timestamp=int.from_bytes(data[4:8], "big"),
            ssrc=int.from_bytes(data[8:12], "big"),
            payload=data[offset:end],
            marker=bool(data[1] & 0x80),
        )


class JitterBuffer:
    """
    Reorders received packets and plays them out with a fixed delay.

    Playout starts once `depth` packets are buffered and then advances one
    sequence number per pop. A missing packet pops as None, a late one is
    dropped. After `depth` empty pops in a row the buffer primes again, so a
    paused or restarted stream does not drift.
    """

    def __init__(self, depth: int = 3) -> None:
        """Create a buffer that holds `depth` packets (20 ms each) of delay."""
        self.depth = depth
        self._packets: dict[int, bytes] = {}
        self._next: int | None = None
        self._empty_pops = 0

    def push(self, sequence: int, payload: bytes) -> None:
        """Add a received packet."""
        if self._next is not None and seq_diff(sequence, self._next) < 0:
            return  # too late, its slot has already been played
        self._packets[sequence] = payload
        if self._next is not None and len(self._packets) > 2 * self.depth:
            # Running behind the sender: skip ahead to keep the delay fixed.
            newest = max(self._packets, key=lambda s: seq_diff(s, self._next))
            self._next = (newest - self.depth + 1) & 0xFFFF
            self._packets = {
                s: p for s, p in self._packets.items() if seq_diff(s, self._next) >= 0
            }

    def pop(self) -> bytes | None:
        """Return the payload due now, or None if there is none."""
        if self._next is None:
            if len(self._packets) < self.depth:
                return None
            self._next = min(
                self._packets, key=lambda s: seq_diff(s, next(iter(self._packets)))
            )
        payload = self._packets.pop(self._next, None)
        self._next = (self._next + 1) & 0xFFFF
        if payload is None and not self._packets:
            self._empty_pops += 1
            if self._empty_pops >= self.depth:
                self._next = None
                self._empty_pops = 0
        else:
            self._empty_pops = 0
        return payload


# ============================================================
# Session
# ============================================================


type FrameListener = Callable[[np.ndarray], None]


class RtpSession(asyncio.DatagramProtocol):
    """
    The audio stream of one call.

    Every 20 ms tick sends one frame and plays one received frame out to the
    listeners (received audio or silence). The frame sent is queued clip audio
    mixed with queued live audio, or silence when neither has any.
    """

    def __init__(
        self,
        *,
        payload_type: int = PCMA,
        remote: tuple[str, int] | None = None,
    ) -> None:
        """
        Create a session sending `payload_type` audio.

        remote: where to send audio, from the other side's SDP. If it is None,
        the source address of the first received packet is used.
        """
        self.payload_type = payload_type
        self.remote = remote
        self.ssrc = random.getrandbits(32)
        self._sequence = random.getrandbits(16)
        self._timestamp = random.getrandbits(32)
        self._first_packet = True
        self.transport: asyncio.DatagramTransport | None = None
        self.jitter = JitterBuffer()
        # 20 ms frames of PCM: clips play in full, live audio is capped.
        self._clip: deque[np.ndarray] = deque()
        self._live: deque[np.ndarray] = deque()
        self._drained = asyncio.Event()
        self._drained.set()
        self._listeners: list[FrameListener] = []
        self._task: asyncio.Task | None = None

    @property
    def payload_type(self) -> int:
        """Return the RTP payload type sent and accepted, PCMA or PCMU."""
        return self._payload_type

    @payload_type.setter
    def payload_type(self, payload_type: int) -> None:
        """Change the codec, before the call starts."""
        if payload_type not in CODEC_NAMES:
            msg = f"Unsupported RTP payload type: {payload_type}"
            raise ValueError(msg)
        self._payload_type = payload_type

    @property
    def running(self) -> bool:
        """Return whether the 20 ms clock is running."""
        return self._task is not None

    @property
    def codec(self) -> str:
        """Return the name of the codec, PCMA or PCMU."""
        return CODEC_NAMES[self.payload_type]

    # asyncio.DatagramProtocol

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Remember the socket."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Buffer a received audio packet."""
        packet = RtpPacket.parse(data)
        if packet is None or packet.payload_type != self.payload_type:
            return  # not RTP, or telephone-event and comfort noise
        if self.remote is None:
            self.remote = addr
        self.jitter.push(packet.sequence, packet.payload)

    def error_received(self, exc: Exception) -> None:
        """Log socket errors, such as ICMP port unreachable."""
        logger.debug("RTP transport error: %s", exc)

    # Sending

    def write_pcm(self, pcm: np.ndarray, *, live: bool = False) -> None:
        """
        Queue 8 kHz int16 PCM to send.

        Clips (the default) play in full, after earlier clips. live: queue it
        for real-time sources such as a microphone instead, mixed over any
        clip, keeping only the newest MAX_LIVE_BACKLOG frames so a slow
        consumer can't build up delay.
        """
        queue = self._live if live else self._clip
        pcm = np.asarray(pcm, dtype=np.int16)
        for offset in range(0, len(pcm), SAMPLES_PER_FRAME):
            frame = pcm[offset : offset + SAMPLES_PER_FRAME]
            if len(frame) < SAMPLES_PER_FRAME:
                frame = np.pad(frame, (0, SAMPLES_PER_FRAME - len(frame)))
            queue.append(frame)
        if live:
            while len(queue) > MAX_LIVE_BACKLOG:
                queue.popleft()
        elif queue:
            self._drained.clear()

    async def drain(self) -> None:
        """Wait until all queued clip audio has been sent."""
        await self._drained.wait()

    def _next_frame(self) -> np.ndarray:
        """Return the next frame to send: clip and live audio mixed."""
        clip = self._clip.popleft() if self._clip else None
        if not self._clip:
            self._drained.set()
        live = self._live.popleft() if self._live else None
        if clip is None:
            return live if live is not None else _SILENT_FRAME
        if live is None:
            return clip
        mixed = clip.astype(np.int32) + live.astype(np.int32)
        return np.clip(mixed, -32768, 32767).astype(np.int16)

    # Receiving

    def subscribe(self, listener: FrameListener) -> Callable[[], None]:
        """Call `listener` with every played-out 20 ms frame of received audio."""
        self._listeners.append(listener)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._listeners.remove(listener)

        return unsubscribe

    # Clock

    def tick(self) -> None:
        """Send one frame and play one received frame out, 20 ms of audio."""
        payload = g711_encode(self._next_frame(), self.payload_type)
        if self.transport is not None and self.remote is not None:
            packet = RtpPacket(
                payload_type=self.payload_type,
                sequence=self._sequence,
                timestamp=self._timestamp,
                ssrc=self.ssrc,
                payload=payload,
                marker=self._first_packet,
            )
            self.transport.sendto(packet.serialize(), self.remote)
            self._first_packet = False
        self._sequence = (self._sequence + 1) & 0xFFFF
        self._timestamp = (self._timestamp + SAMPLES_PER_FRAME) & 0xFFFFFFFF

        received = self.jitter.pop()
        if self._listeners:
            pcm = (
                g711_decode(received, self.payload_type)
                if received is not None
                else np.zeros(SAMPLES_PER_FRAME, dtype=np.int16)
            )
            for listener in list(self._listeners):
                try:
                    listener(pcm)
                except Exception:
                    logger.exception("Error in RTP frame listener")

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        next_tick = loop.time()
        while True:
            self.tick()
            next_tick += PTIME
            lag = loop.time() - next_tick
            if lag > MAX_TICK_LAG * PTIME:
                next_tick = loop.time()  # the loop stalled; don't send a burst
            await asyncio.sleep(max(0.0, next_tick - loop.time()))

    def start(self) -> None:
        """Start the 20 ms clock."""
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="sip-rtp-clock")

    def close(self) -> None:
        """Stop the clock and close the socket."""
        if self._task is not None:
            self._task.cancel()
            self._task = None
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        self._clip.clear()
        self._live.clear()
        self._drained.set()
        self._listeners.clear()


class RtpPortPool:
    """The local UDP ports available for RTP, one per call."""

    def __init__(self, ports: range) -> None:
        """Create a pool of `ports`."""
        self._free = list(ports)

    def acquire(self) -> int | None:
        """Take a free port, or return None if all are in use."""
        return self._free.pop(0) if self._free else None

    def release(self, port: int) -> None:
        """Give a port back."""
        if port not in self._free:
            self._free.append(port)


type RtpEndpointFactory = Callable[[RtpSession, str, int], Awaitable[None]]


async def open_udp_endpoint(session: RtpSession, host: str, port: int) -> None:
    """Bind `session` to a UDP socket on host:port."""
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: session, local_addr=(host, port))
