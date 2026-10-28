"""Tests for the MiniSIP audio handling."""

import asyncio
import io
import unittest

import numpy as np
import soundfile as sf

from custom_components.sg_150.sip.minisip import (
    MiniSIPServer,
    convert_audio_to_pcma,
)
from custom_components.sg_150.sip.rtp import PCMA, RtpPacket, g711_encode
from tests.utils import FakeTransport, fake_rtp_endpoint


def _invite(call_id: str) -> dict[str, str]:
    """Return a parsed INVITE offering PCMA on 192.168.1.20:4000."""
    return {
        "Via": "SIP/2.0/UDP 192.168.1.20:5060;branch=z123",
        "From": "<sip:123@192.168.1.20>",
        "To": "<sip:456@127.0.0.1>",
        "Call-ID": call_id,
        "CSeq": "1 INVITE",
        "Contact": "<sip:123@192.168.1.20>",
        "Content-Type": "application/sdp",
        ":body": (
            "v=0\r\n"
            "o=- 1 1 IN IP4 192.168.1.20\r\n"
            "s=call\r\n"
            "c=IN IP4 192.168.1.20\r\n"
            "t=0 0\r\n"
            "m=audio 4000 RTP/AVP 8\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=ptime:20\r\n"
            "a=sendrecv\r\n"
        ),
        ":start_line": "INVITE sip:456@127.0.0.1 SIP/2.0",
    }


class MiniSIPAudioTests(unittest.IsolatedAsyncioTestCase):
    """Unit tests for MiniSIP audio handling."""

    async def test_parse_sdp_media_from_invite_response(self) -> None:
        """Test parsing SDP media from an INVITE response."""
        sdp = (
            "v=0\r\n"
            "o=- 123 123 IN IP4 192.168.1.20\r\n"
            "s=call\r\n"
            "c=IN IP4 192.168.1.20\r\n"
            "t=0 0\r\n"
            "m=audio 4000 RTP/AVP 8 101\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=ptime:20\r\n"
            "a=sendrecv\r\n"
        )

        media = MiniSIPServer.parse_sdp_media(sdp)

        assert media["ip"] == "192.168.1.20"
        assert media["port"] == 4000
        assert media["payload_type"] == 8
        assert media["codec"] == "PCMA"
        assert media["ptime"] == 20
        assert media["direction"] == "sendrecv"

    async def test_play_audio_is_sent_from_the_rtp_port_to_the_negotiated_one(
        self,
    ) -> None:
        """Played audio leaves the call's RTP socket, not the SIP socket."""
        server = MiniSIPServer(
            {"user": "pass"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            rtp_endpoint=fake_rtp_endpoint,
        )
        server.transport = FakeTransport()
        await server.handle_invite(_invite("call-123"), ("192.168.1.20", 5060))
        await server.handle_ack({"Call-ID": "call-123"}, ("192.168.1.20", 5060))
        session = server.rtp_session("call-123")
        sip_sent = len(server.transport.sent)

        wav = io.BytesIO()
        sf.write(wav, np.full(320, 1000, dtype=np.int16), 8000, format="WAV")
        await asyncio.wait_for(
            server.play_audio("call-123", "audio/wav", wav.getvalue()), timeout=1
        )

        assert len(server.transport.sent) == sip_sent
        assert {addr for _, addr in session.transport.sent} == {("192.168.1.20", 4000)}
        assert session.transport.local_addr == ("127.0.0.1", 5004)
        packets = [RtpPacket.parse(data) for data, _ in session.transport.sent]
        assert {p.payload_type for p in packets} == {8}
        assert packets[0].marker
        clip = g711_encode(np.full(160, 1000), PCMA)
        assert [p.payload for p in packets].count(clip) == 2
        sequences = [p.sequence for p in packets]
        assert sequences == [(sequences[0] + i) & 0xFFFF for i in range(len(packets))]

    async def test_convert_audio_to_pcma_from_wav(self) -> None:
        """Test converting audio from WAV MIME data to PCMA."""
        wav_buffer = io.BytesIO()
        samples = np.zeros(160, dtype=np.int16)
        sf.write(wav_buffer, samples, 8000, format="WAV", subtype="PCM_16")
        wav_buffer.seek(0)

        pcma = convert_audio_to_pcma(wav_buffer.getvalue(), "audio/wav")

        assert len(pcma) == 160
        assert all(0 <= byte <= 255 for byte in pcma)

    async def test_convert_audio_to_pcma_from_mp3(self) -> None:
        """Test converting audio from MP3 MIME data to PCMA."""
        mp3_buffer = io.BytesIO()
        samples = np.zeros(160, dtype=np.int16)
        sf.write(mp3_buffer, samples, 8000, format="MP3")
        mp3_buffer.seek(0)

        pcma = convert_audio_to_pcma(mp3_buffer.getvalue(), "audio/mpeg")

        assert len(pcma) > 0
        assert all(0 <= byte <= 255 for byte in pcma)

    async def test_handle_invite_accepts_call_and_parses_sdp(self) -> None:
        """Test a received INVITE is accepted and its SDP media is stored."""
        server = MiniSIPServer(
            {"user": "pass"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            rtp_endpoint=fake_rtp_endpoint,
        )
        server.transport = FakeTransport()

        await server.handle_invite(_invite("call-123"), ("192.168.1.20", 5060))
        await server.handle_ack({"Call-ID": "call-123"}, ("192.168.1.20", 5060))

        assert "call-123" in server.active_calls
        assert server.active_calls["call-123"].addr == ("192.168.1.20", 5060)
        assert server.active_calls["call-123"].media["ip"] == "192.168.1.20"
        assert server.active_calls["call-123"].media["port"] == 4000
        assert server.active_calls["call-123"].media["payload_type"] == 8
        assert len(server.transport.sent) >= 2
        assert all(isinstance(item, tuple) for item in server.transport.sent)


if __name__ == "__main__":
    unittest.main()
