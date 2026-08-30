"""Tests for the MiniSIP audio handling."""

import io
import unittest

import numpy as np
import soundfile as sf

from custom_components.sg_150.sip.minisip import (
    MiniSIPServer,
    convert_audio_to_pcma,
)
from tests.utils import FakeTransport


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

    async def test_send_rtp_audio_uses_negotiated_media_port(self) -> None:
        """Test sending RTP audio uses the negotiated media port."""
        server = MiniSIPServer(
            {"user": "pass"}, host="127.0.0.1", call_host="127.0.0.1"
        )
        server.active_calls["call-123"] = (
            ("192.168.1.20", 5060),
            "From: <sip:123@127.0.0.1>",
            "To: <sip:456@192.168.1.20>",
            None,
            {
                "ip": "192.168.1.20",
                "port": 4000,
                "payload_type": 8,
                "codec": "PCMA",
                "ptime": 20,
                "direction": "sendrecv",
            },
        )
        server.transport = FakeTransport()

        pcm = b"\x00\x00" * 160

        await server.send_rtp_audio("call-123", pcm)

        assert len(server.transport.sent) == 1
        data, addr = server.transport.sent[0]
        assert addr == ("192.168.1.20", 4000)
        assert data[0] == 128  # RTP version 2, no marker on first packet
        assert data[1] == 8  # payload type 8 (PCMA)
        assert len(data) > 12

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
            {"user": "pass"}, host="127.0.0.1", call_host="127.0.0.1"
        )
        server.transport = FakeTransport()

        invite = {
            "Via": "SIP/2.0/UDP 192.168.1.20:5060;branch=z123",
            "From": "<sip:123@192.168.1.20>",
            "To": "<sip:456@127.0.0.1>",
            "Call-ID": "call-123",
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

        await server.handle_invite(invite, ("192.168.1.20", 5060))

        assert "call-123" in server.active_calls
        assert server.active_calls["call-123"][0] == ("192.168.1.20", 5060)
        assert server.active_calls["call-123"][4]["ip"] == "192.168.1.20"
        assert server.active_calls["call-123"][4]["port"] == 4000
        assert server.active_calls["call-123"][4]["payload_type"] == 8
        assert len(server.transport.sent) >= 2
        assert all(isinstance(item, tuple) for item in server.transport.sent)


if __name__ == "__main__":
    unittest.main()
