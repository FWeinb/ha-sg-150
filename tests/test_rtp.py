"""Tests for the RTP media layer."""

import asyncio
import io
import unittest

import numpy as np
import pytest
import soundfile as sf

from custom_components.sg_150.sip.rtp import (
    MAX_LIVE_BACKLOG,
    PCMA,
    PCMU,
    SAMPLES_PER_FRAME,
    JitterBuffer,
    RtpPacket,
    RtpPortPool,
    RtpSession,
    g711_decode,
    g711_encode,
)
from tests.utils import FakeTransport

GATEWAY_RTP = ("10.5.1.6", 10024)
ALL_SAMPLES = np.arange(-32768, 32768, dtype=np.int16)


def _libsndfile(samples: np.ndarray, subtype: str) -> bytes:
    buffer = io.BytesIO()
    sf.write(buffer, samples, 8000, format="RAW", subtype=subtype)
    return buffer.getvalue()


def _packet(sequence: int, payload: bytes = b"\xd5" * 160, pt: int = PCMA) -> bytes:
    return RtpPacket(pt, sequence, sequence * 160, 1234, payload).serialize()


class G711Tests(unittest.TestCase):
    """The G.711 tables match libsndfile, which the clip conversion uses."""

    def test_encoding_is_as_accurate_as_libsndfile(self) -> None:
        """
        Every int16 value encodes like libsndfile, or to a neighbouring code.

        The two differ only in how negative values on a step boundary round, so
        the worst-case error over the whole range is the same.
        """
        for pt, subtype in ((PCMA, "ALAW"), (PCMU, "ULAW")):
            ours = g711_encode(ALL_SAMPLES, pt)
            theirs = _libsndfile(ALL_SAMPLES, subtype)
            differ = np.frombuffer(ours, np.uint8) != np.frombuffer(theirs, np.uint8)

            assert (ALL_SAMPLES[differ] < 0).all()
            assert differ.mean() < 0.01
            error = np.abs(g711_decode(ours, pt).astype(int) - ALL_SAMPLES)
            reference = np.abs(g711_decode(theirs, pt).astype(int) - ALL_SAMPLES)
            assert error.max() == reference.max()

    def test_decoding_matches_libsndfile(self) -> None:
        """Every code decodes to the same linear value."""
        codes = bytes(range(256))
        for pt, subtype in ((PCMA, "ALAW"), (PCMU, "ULAW")):
            expected, _ = sf.read(
                io.BytesIO(codes),
                dtype="int16",
                format="RAW",
                subtype=subtype,
                samplerate=8000,
                channels=1,
            )
            np.testing.assert_array_equal(g711_decode(codes, pt), expected)

    def test_silence(self) -> None:
        """Silence is the usual 0xD5 for A-law and 0xFF for µ-law."""
        assert g711_encode(np.zeros(2), PCMA) == b"\xd5\xd5"
        assert g711_encode(np.zeros(2), PCMU) == b"\xff\xff"


class RtpPacketTests(unittest.TestCase):
    """RTP packet parsing and serialization."""

    def test_round_trip(self) -> None:
        """A serialized packet parses back to the same packet."""
        packet = RtpPacket(8, 65535, 2**32 - 1, 0xDEADBEEF, b"abc", marker=True)

        assert RtpPacket.parse(packet.serialize()) == packet

    def test_parse_skips_csrcs_extension_and_padding(self) -> None:
        """The payload starts after CSRCs and the extension, and ends before padding."""
        header = bytes([0x80 | 0x20 | 0x10 | 1, 8]) + bytes(10)
        csrc = bytes(4)
        extension = b"\xbe\xde\x00\x01" + bytes(4)
        padding = b"\x00\x00\x03"

        packet = RtpPacket.parse(header + csrc + extension + b"voice" + padding)

        assert packet.payload == b"voice"

    def test_parse_rejects_other_datagrams(self) -> None:
        """Short datagrams and other RTP versions are not packets."""
        assert RtpPacket.parse(b"\x80\x08") is None
        assert RtpPacket.parse(bytes([0x40]) + bytes(20)) is None


class JitterBufferTests(unittest.TestCase):
    """The jitter buffer reorders, drops late packets and keeps its delay."""

    def test_waits_for_depth_then_plays_in_order(self) -> None:
        """Playout starts after `depth` packets, in sequence order."""
        buffer = JitterBuffer(depth=3)
        buffer.push(11, b"b")
        buffer.push(10, b"a")
        assert buffer.pop() is None

        buffer.push(12, b"c")

        assert [buffer.pop() for _ in range(3)] == [b"a", b"b", b"c"]

    def test_lost_packet_pops_none_and_late_packet_is_dropped(self) -> None:
        """A gap plays as None; the missing packet arriving later is ignored."""
        buffer = JitterBuffer(depth=2)
        for seq in (1, 3, 4):
            buffer.push(seq, bytes([seq]))

        assert buffer.pop() == b"\x01"
        assert buffer.pop() is None
        buffer.push(2, b"\x02")
        assert buffer.pop() == b"\x03"
        assert buffer.pop() == b"\x04"

    def test_sequence_wrap_around(self) -> None:
        """Sequence 0 follows 65535."""
        buffer = JitterBuffer(depth=2)
        buffer.push(0, b"b")
        buffer.push(65535, b"a")

        assert [buffer.pop(), buffer.pop()] == [b"a", b"b"]

    def test_primes_again_after_the_stream_pauses(self) -> None:
        """After `depth` empty pops, a restarted stream is buffered afresh."""
        buffer = JitterBuffer(depth=2)
        buffer.push(1, b"a")
        buffer.push(2, b"b")
        assert [buffer.pop(), buffer.pop()] == [b"a", b"b"]
        assert [buffer.pop(), buffer.pop()] == [None, None]

        buffer.push(500, b"x")
        assert buffer.pop() is None
        buffer.push(501, b"y")

        assert [buffer.pop(), buffer.pop()] == [b"x", b"y"]

    def test_skips_ahead_when_the_sender_runs_fast(self) -> None:
        """More than twice the depth buffered skips ahead to `depth` packets."""
        buffer = JitterBuffer(depth=2)
        buffer.push(1, b"1")
        buffer.push(2, b"2")
        assert buffer.pop() == b"1"
        for seq in range(3, 7):
            buffer.push(seq, str(seq).encode())

        assert [buffer.pop(), buffer.pop()] == [b"5", b"6"]


class RtpSessionTests(unittest.IsolatedAsyncioTestCase):
    """RtpSession sends one frame and plays one frame out per tick."""

    def _session(self, **kwargs: object) -> tuple[RtpSession, FakeTransport]:
        session = RtpSession(**kwargs)
        transport = FakeTransport()
        session.connection_made(transport)
        return session, transport

    def _sent(self, transport: FakeTransport) -> list[RtpPacket]:
        return [RtpPacket.parse(data) for data, _ in transport.sent]

    def test_sends_silence_when_idle_with_advancing_headers(self) -> None:
        """Idle ticks send marked-then-unmarked silence, 160 samples apart."""
        session, transport = self._session(remote=GATEWAY_RTP)

        session.tick()
        session.tick()

        first, second = self._sent(transport)
        assert first.payload == b"\xd5" * 160
        assert first.marker
        assert not second.marker
        assert second.sequence == (first.sequence + 1) & 0xFFFF
        assert second.timestamp == (first.timestamp + 160) & 0xFFFFFFFF
        assert first.ssrc == second.ssrc == session.ssrc
        assert {addr for _, addr in transport.sent} == {GATEWAY_RTP}

    def test_ssrc_and_sequence_are_random_per_session(self) -> None:
        """Two sessions do not share the old fixed SSRC."""
        sessions = [RtpSession() for _ in range(4)]

        assert len({s.ssrc for s in sessions}) > 1
        assert 0x12345678 not in {s.ssrc for s in sessions}

    def test_learns_the_remote_from_the_first_packet(self) -> None:
        """Without an SDP address, audio goes back to where packets come from."""
        session, transport = self._session()
        session.tick()
        assert transport.sent == []

        session.datagram_received(_packet(1), GATEWAY_RTP)
        session.datagram_received(_packet(2), ("10.9.9.9", 1))
        session.tick()

        assert transport.sent[0][1] == GATEWAY_RTP

    def test_sdp_remote_wins_over_packet_source(self) -> None:
        """The SDP address is kept even if packets come from elsewhere."""
        session, transport = self._session(remote=("10.5.1.6", 4000))

        session.datagram_received(_packet(1), GATEWAY_RTP)
        session.tick()

        assert transport.sent[0][1] == ("10.5.1.6", 4000)

    async def test_written_pcm_is_sent_in_frames_then_drained(self) -> None:
        """PCM is split into 20 ms frames, padded, and drain() completes after."""
        session, transport = self._session(remote=GATEWAY_RTP)
        session.write_pcm(np.full(SAMPLES_PER_FRAME + 10, 1000))

        drained = asyncio.create_task(session.drain())
        await asyncio.sleep(0)
        assert not drained.done()
        for _ in range(3):
            session.tick()
        await asyncio.wait_for(drained, timeout=1)

        tone = g711_encode(np.full(SAMPLES_PER_FRAME, 1000), PCMA)
        padded = g711_encode(
            np.r_[np.full(10, 1000), np.zeros(SAMPLES_PER_FRAME - 10)], PCMA
        )
        assert [p.payload for p in self._sent(transport)] == [
            tone,
            padded,
            b"\xd5" * 160,
        ]

    def test_live_audio_backlog_is_capped(self) -> None:
        """A live source never queues more than MAX_LIVE_BACKLOG frames."""
        session, transport = self._session(remote=GATEWAY_RTP)
        frames = MAX_LIVE_BACKLOG + 5
        pcm = np.repeat(np.arange(frames, dtype=np.int16) * 100, SAMPLES_PER_FRAME)

        session.write_pcm(pcm, live=True)
        for _ in range(frames):
            session.tick()

        payloads = [p.payload for p in self._sent(transport)]
        first_kept = g711_encode(np.full(SAMPLES_PER_FRAME, 500), PCMA)
        assert payloads[0] == first_kept
        assert payloads[MAX_LIVE_BACKLOG:] == [b"\xd5" * 160] * 5

    async def test_live_audio_mixes_over_a_clip_without_cutting_it(self) -> None:
        """Talking during a clip mixes in; the whole clip still plays."""
        session, transport = self._session(remote=GATEWAY_RTP)
        clip_frames = MAX_LIVE_BACKLOG * 3
        session.write_pcm(np.full(clip_frames * SAMPLES_PER_FRAME, 1000))
        drained = asyncio.create_task(session.drain())

        session.tick()
        session.write_pcm(np.full(2 * SAMPLES_PER_FRAME, 30000), live=True)
        for _ in range(clip_frames - 2):
            session.tick()
        await asyncio.sleep(0)
        assert not drained.done()  # the clip's last frame is still queued

        session.tick()
        await asyncio.wait_for(drained, timeout=1)
        payloads = [p.payload for p in self._sent(transport)]
        clip = g711_encode(np.full(SAMPLES_PER_FRAME, 1000), PCMA)
        loud = g711_encode(np.full(SAMPLES_PER_FRAME, 31000), PCMA)
        mixed_to_limit = g711_encode(np.full(SAMPLES_PER_FRAME, 32767), PCMA)
        assert len(payloads) == clip_frames
        assert payloads[0] == clip
        # 1000 + 30000 stays in range; it isn't the clipped maximum.
        assert payloads[1:3] == [loud, loud]
        assert loud != mixed_to_limit
        assert payloads[3:] == [clip] * (clip_frames - 3)

    def test_mixing_clips_at_the_int16_range(self) -> None:
        """Loud clip plus loud live audio saturates instead of wrapping."""
        session, transport = self._session(remote=GATEWAY_RTP)
        session.write_pcm(np.full(SAMPLES_PER_FRAME, -30000))
        session.write_pcm(np.full(SAMPLES_PER_FRAME, -30000), live=True)

        session.tick()

        assert self._sent(transport)[0].payload == g711_encode(
            np.full(SAMPLES_PER_FRAME, -32768), PCMA
        )

    async def test_live_audio_alone_does_not_hold_drain(self) -> None:
        """drain() is for clips; queued live audio leaves it complete."""
        session, _ = self._session(remote=GATEWAY_RTP)

        session.write_pcm(np.full(SAMPLES_PER_FRAME, 1000), live=True)

        await asyncio.wait_for(session.drain(), timeout=0.1)

    def test_received_audio_is_decoded_for_listeners(self) -> None:
        """Listeners get decoded audio once buffered, and silence before."""
        session, _ = self._session(payload_type=PCMU)
        frames: list[np.ndarray] = []
        unsubscribe = session.subscribe(frames.append)
        tone = g711_encode(np.full(SAMPLES_PER_FRAME, 1000), PCMU)
        for seq in range(3):
            session.datagram_received(_packet(seq, tone, PCMU), GATEWAY_RTP)
        session.datagram_received(_packet(9, b"\x00", 101), GATEWAY_RTP)

        session.tick()
        unsubscribe()
        session.tick()

        assert len(frames) == 1
        np.testing.assert_array_equal(frames[0], g711_decode(tone, PCMU))

    def test_changing_the_codec_changes_silence(self) -> None:
        """Silence follows the negotiated payload type."""
        session, transport = self._session(remote=GATEWAY_RTP)
        session.payload_type = PCMU

        session.tick()

        assert self._sent(transport)[0].payload == b"\xff" * 160

    def test_unsupported_codec_is_refused(self) -> None:
        """Only PCMA and PCMU can be sent."""
        with pytest.raises(ValueError, match="Unsupported RTP payload type"):
            RtpSession(payload_type=9)

    async def test_clock_ticks_every_20ms_until_closed(self) -> None:
        """start() sends about one packet per 20 ms; close() stops and closes."""
        session, transport = self._session(remote=GATEWAY_RTP)
        closed = []
        transport.close = lambda: closed.append(True)

        session.start()
        await asyncio.sleep(0.105)
        session.close()
        sent = len(transport.sent)
        await asyncio.sleep(0.05)

        assert 4 <= sent <= 7
        assert len(transport.sent) == sent
        assert closed == [True]
        assert session.transport is None


class RtpPortPoolTests(unittest.TestCase):
    """Ports are handed out once and come back on release."""

    def test_acquire_and_release(self) -> None:
        """The pool runs out, and released ports are reused."""
        pool = RtpPortPool(range(5004, 5006))

        assert [pool.acquire(), pool.acquire(), pool.acquire()] == [5004, 5005, None]
        pool.release(5004)
        pool.release(5004)
        assert [pool.acquire(), pool.acquire()] == [5004, None]


if __name__ == "__main__":
    unittest.main()
