"""Behavioral tests for the MiniSIP server."""

import asyncio
import re
import unittest
from unittest.mock import patch

import pytest

from custom_components.sg_150.sip import minisip
from custom_components.sg_150.sip.minisip import (
    CallContext,
    IncomingCallDecision,
    MiniSIPServer,
    SIPDialog,
    md5_hex,
)
from tests.sip_messages import GATEWAY, HA_NUMBER, ack, bye, cancel, invite, sip
from tests.utils import FakeTransport, fake_rtp_endpoint


class MiniSIPBehaviorTests(unittest.IsolatedAsyncioTestCase):
    """Behavior-level tests for MiniSIP SIP flow."""

    async def test_register_with_valid_digest_registers_user(self) -> None:
        """A valid REGISTER digest should update the user registration."""
        server = MiniSIPServer(
            {"alice": "secret"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            realm="example",
            rtp_endpoint=fake_rtp_endpoint,
        )
        server.transport = FakeTransport()

        challenge = server.create_unauthorized_response(
            {
                "Call-ID": "register-1",
                "CSeq": "1 REGISTER",
                "From": "<sip:alice@127.0.0.1>",
                "To": "<sip:alice@127.0.0.1>",
                "Via": "SIP/2.0/UDP 192.168.1.50:5060",
            }
        )
        challenge_text = challenge.decode()
        nonce = re.search(r'nonce="([^"]+)"', challenge_text).group(1)
        opaque = re.search(r'opaque="([^"]+)"', challenge_text).group(1)

        ha1 = md5_hex("alice:example:secret")
        uri = "sip:alice@127.0.0.1"
        ha2 = md5_hex(f"REGISTER:{uri}")
        cnonce = "abc123"
        response = md5_hex(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")

        message = {
            "Call-ID": "register-1",
            "CSeq": "1 REGISTER",
            "Authorization": (
                f'Digest username="alice", realm="example", nonce="{nonce}", '
                f'uri="{uri}", response="{response}", algorithm=MD5, '
                f'qop=auth, nc=00000001, cnonce="{cnonce}", opaque="{opaque}"'
            ),
            "Expires": "300",
            "From": "<sip:alice@127.0.0.1>",
            "To": "<sip:alice@127.0.0.1>",
            "Via": "SIP/2.0/UDP 192.168.1.50:5060",
        }

        await server.handle_register(message, ("192.168.1.50", 5060))

        assert "alice" in server.registrations
        assert server.registrations["alice"].addr == ("192.168.1.50", 5060)
        assert server.transport.sent
        assert server.transport.sent[-1][0].startswith(b"SIP/2.0 200 OK")

    async def test_handle_invite_accepts_call_and_tracks_active_session(self) -> None:
        """An incoming INVITE should be accepted and stored as an active call."""
        server = MiniSIPServer(
            {"alice": "secret"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            rtp_endpoint=fake_rtp_endpoint,
        )
        server.transport = FakeTransport()

        seen = []

        async def on_incoming_call(call_context: CallContext) -> None:
            seen.append(call_context.call_id)
            return True

        server.add_listener("on_incoming_call", on_incoming_call)

        message = {
            "Via": "SIP/2.0/UDP 192.168.1.10:5060",
            "From": "<sip:1001@192.168.1.10>",
            "To": "<sip:2000@127.0.0.1>",
            "Call-ID": "call-123",
            "CSeq": "1 INVITE",
            "Contact": "<sip:1001@192.168.1.10>",
        }

        await server.handle_invite(message, ("192.168.1.10", 5060))
        await server.handle_ack(
            {"Call-ID": "call-123", "CSeq": "1 ACK"}, ("192.168.1.10", 5060)
        )

        assert seen == ["call-123"]
        assert len(server.transport.sent) == 2
        assert server.transport.sent[0][0].startswith(b"SIP/2.0 180 Ringing")
        assert server.transport.sent[1][0].startswith(b"SIP/2.0 200 OK")
        assert "call-123" in server.active_calls
        assert server.active_calls["call-123"].addr == ("192.168.1.10", 5060)

    async def test_handle_bye_closes_call_and_returns_ok(self) -> None:
        """BYE should close the active call and answer with a success response."""
        server = MiniSIPServer(
            {"alice": "secret"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            rtp_endpoint=fake_rtp_endpoint,
        )
        server.transport = FakeTransport()
        server.active_calls["call-456"] = SIPDialog(
            call_id="call-456",
            direction="incoming",
            addr=("192.168.1.10", 5060),
            from_header="<sip:1001@192.168.1.10>",
            to_header="<sip:2000@127.0.0.1>",
            contact="<sip:1001@192.168.1.10>",
        )

        await server.handle_bye(
            {"Call-ID": "call-456", "CSeq": "2 BYE"}, ("192.168.1.10", 5060)
        )

        assert "call-456" not in server.active_calls
        assert server.transport.sent
        assert server.transport.sent[0][0].startswith(b"SIP/2.0 200 OK")


class MiniSIPDatagramTests(unittest.IsolatedAsyncioTestCase):
    """SIP behaviour driven through handle_datagram."""

    def setUp(self) -> None:
        """Create a server with a fake transport and record call events."""
        self.server = MiniSIPServer(
            {"alice": "secret"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            port=5070,
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.server.transport = FakeTransport()
        self.established: list[str] = []
        self.ended: list[str] = []

        async def on_established(dialog: SIPDialog) -> None:
            self.established.append(dialog.call_id)

        async def on_ended(dialog: SIPDialog) -> None:
            self.ended.append(dialog.call_id)

        self.server.add_listener("on_call_established", on_established)
        self.server.add_listener("on_call_ended", on_ended)

    def _sent(self) -> list[str]:
        return [data.decode() for data, _ in self.server.transport.sent]

    async def test_incoming_call_is_established_only_after_ack(self) -> None:
        """The call becomes active when the ACK for our 200 OK arrives."""
        await self.server.handle_datagram(invite("c1", "*111", HA_NUMBER), GATEWAY)

        assert self._sent()[-1].startswith("SIP/2.0 200 OK")
        assert self.established == []
        assert "c1" not in self.server.active_calls

        await self.server.handle_datagram(ack("c1"), GATEWAY)

        assert self.established == ["c1"]
        assert self.server.active_calls["c1"].media["port"] == 4000

    async def test_ok_contact_points_at_our_sip_port(self) -> None:
        """The gateway must send its ACK to the port we listen on."""
        await self.server.handle_datagram(invite("c2", "*111", HA_NUMBER), GATEWAY)

        assert f"Contact: <sip:{HA_NUMBER}@127.0.0.1:5070>" in self._sent()[-1]

    async def test_bye_before_ack_drops_the_call_without_events(self) -> None:
        """A call that never got its ACK is dropped and was never established."""
        await self.server.handle_datagram(invite("c3", "*111", HA_NUMBER), GATEWAY)
        await self.server.handle_datagram(bye("c3"), GATEWAY)
        await self.server.handle_datagram(ack("c3"), GATEWAY)

        assert self._sent()[-1].startswith("SIP/2.0 200 OK")
        assert self.established == []
        assert self.ended == []
        assert "c3" not in self.server.active_calls

    async def test_options_is_answered(self) -> None:
        """OPTIONS gets a 200 OK listing the supported methods."""
        await self.server.handle_datagram(self._options("o1", 1), GATEWAY)

        response = self._sent()[-1]
        assert response.startswith("SIP/2.0 200 OK")
        assert "Allow: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS" in response

    async def test_options_with_old_cseq_is_rejected(self) -> None:
        """An out-of-order OPTIONS gets a 400 that is actually sent."""
        await self.server.handle_datagram(self._options("o2", 5), GATEWAY)
        await self.server.handle_datagram(self._options("o2", 1), GATEWAY)

        assert len(self._sent()) == 2
        assert self._sent()[-1].startswith("SIP/2.0 400 Bad Request")

    def _ring(self) -> None:
        async def ring(_: CallContext) -> IncomingCallDecision:
            return IncomingCallDecision.RING

        self.server.add_listener("on_incoming_call", ring)

    async def test_answer_sdp_offers_sendrecv_on_the_calls_rtp_port(self) -> None:
        """Our 200 OK answers PCMA, sendrecv, on the port the RTP session has."""
        await self.server.handle_datagram(invite("c4", "*111", HA_NUMBER), GATEWAY)

        answer = self._sent()[-1]
        assert "m=audio 5004 RTP/AVP 8\r\n" in answer
        assert "a=sendrecv" in answer
        assert self.server.rtp_sessions["c4"].remote == ("192.168.1.10", 4000)

    async def test_pcmu_offer_is_answered_with_pcmu(self) -> None:
        """A gateway offering only PCMU gets a PCMU session."""
        data = invite("c5", "*111", HA_NUMBER).replace(
            b"RTP/AVP 8\r\na=rtpmap:8 PCMA/8000", b"RTP/AVP 0"
        )

        await self.server.handle_datagram(data, GATEWAY)

        assert "m=audio 5004 RTP/AVP 0\r\n" in self._sent()[-1]
        assert self.server.rtp_sessions["c5"].codec == "PCMU"

    async def test_rtp_session_runs_from_ack_until_bye(self) -> None:
        """The RTP clock starts on ACK, and BYE closes it and frees the port."""
        await self.server.handle_datagram(invite("c6", "*111", HA_NUMBER), GATEWAY)
        session = self.server.rtp_sessions["c6"]
        assert not session.running

        await self.server.handle_datagram(ack("c6"), GATEWAY)
        assert session.running

        await self.server.handle_datagram(bye("c6"), GATEWAY)
        assert session.transport is None
        assert "c6" not in self.server.rtp_sessions

    async def test_ended_call_gives_its_rtp_port_back(self) -> None:
        """With a single RTP port, a second call can use it after the first."""
        self.server = MiniSIPServer(
            {},
            call_host="127.0.0.1",
            rtp_ports=range(5004, 5005),
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.server.transport = FakeTransport()
        await self.server.handle_datagram(invite("c6", "*111", HA_NUMBER), GATEWAY)
        await self.server.handle_datagram(ack("c6"), GATEWAY)
        await self.server.handle_datagram(bye("c6"), GATEWAY)

        await self.server.handle_datagram(invite("c6b", "*111", HA_NUMBER), GATEWAY)

        assert "m=audio 5004 " in self._sent()[-1]

    async def test_no_free_rtp_port_answers_service_unavailable(self) -> None:
        """When every RTP port is in use, the call is refused with 503."""
        self.server = MiniSIPServer(
            {},
            call_host="127.0.0.1",
            rtp_ports=range(0),
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.server.transport = FakeTransport()

        await self.server.handle_datagram(invite("c7", "*111", HA_NUMBER), GATEWAY)

        assert self._sent()[-1].startswith("SIP/2.0 503 Service Unavailable")
        assert "c7" not in self.server.pending_acks

    async def test_ok_is_resent_until_ack(self) -> None:
        """A lost 200 OK or ACK is covered by resending the 200 OK."""
        with (
            patch.object(minisip, "TIMER_T1", 0.01),
            patch.object(minisip, "TIMER_T2", 0.02),
        ):
            await self.server.handle_datagram(invite("c8", "*111", HA_NUMBER), GATEWAY)
            await asyncio.sleep(0.05)
            await self.server.handle_datagram(ack("c8"), GATEWAY)
            sent = len(self._sent())
            await asyncio.sleep(0.05)

        oks = [m for m in self._sent() if m.startswith("SIP/2.0 200 OK")]
        assert len(oks) >= 3
        assert len(self._sent()) == sent
        assert self.established == ["c8"]

    async def test_missing_ack_gives_up_and_frees_the_rtp_port(self) -> None:
        """Without an ACK after 64 * T1 the call is dropped."""
        with (
            patch.object(minisip, "TIMER_T1", 0.001),
            patch.object(minisip, "TIMER_T2", 0.004),
        ):
            await self.server.handle_datagram(invite("c9", "*111", HA_NUMBER), GATEWAY)
            await asyncio.sleep(0.3)

        assert "c9" not in self.server.pending_acks
        assert "c9" not in self.server.rtp_sessions
        await self.server.handle_datagram(ack("c9"), GATEWAY)
        assert self.established == []

    async def test_retransmitted_invite_is_ignored(self) -> None:
        """A second INVITE with the same Call-ID doesn't start a second call."""
        await self.server.handle_datagram(invite("c10", "*111", HA_NUMBER), GATEWAY)
        sent = len(self._sent())

        await self.server.handle_datagram(invite("c10", "*111", HA_NUMBER), GATEWAY)

        assert len(self._sent()) == sent
        assert list(self.server.rtp_sessions) == ["c10"]

    async def test_ringing_call_is_answered_later(self) -> None:
        """RING sends only 180 Ringing; answer_call sends the 200 OK."""
        self._ring()

        await self.server.handle_datagram(invite("r1", "*111", HA_NUMBER), GATEWAY)

        assert [m.split("\r\n")[0] for m in self._sent()] == ["SIP/2.0 180 Ringing"]
        assert "r1" in self.server.ringing
        assert "r1" not in self.server.rtp_sessions

        await self.server.answer_call("r1")
        await self.server.handle_datagram(ack("r1"), GATEWAY)

        assert self._sent()[-1].startswith("SIP/2.0 200 OK")
        assert ";tag=minisip" in self._sent()[-1]
        assert self.established == ["r1"]

    async def test_ringing_call_can_be_rejected(self) -> None:
        """reject_call answers 486 Busy Here."""
        self._ring()
        await self.server.handle_datagram(invite("r2", "*111", HA_NUMBER), GATEWAY)

        await self.server.reject_call("r2")

        assert self._sent()[-1].startswith("SIP/2.0 486 Busy Here")
        assert not self.server.ringing
        with pytest.raises(ValueError, match="no ringing call"):
            await self.server.answer_call("r2")

    async def test_cancel_ends_a_ringing_call(self) -> None:
        """CANCEL is confirmed with 200, and the INVITE ends with 487."""
        self._ring()
        cancelled: list[str] = []

        async def on_cancelled(call_id: str) -> None:
            cancelled.append(call_id)

        self.server.add_listener("on_call_cancelled", on_cancelled)
        await self.server.handle_datagram(invite("r3", "*111", HA_NUMBER), GATEWAY)

        await self.server.handle_datagram(cancel("r3"), GATEWAY)

        statuses = [m.split("\r\n")[0] for m in self._sent()]
        assert statuses[-2:] == ["SIP/2.0 200 OK", "SIP/2.0 487 Request Terminated"]
        assert "CSeq: 1 CANCEL" in self._sent()[-2]
        assert "CSeq: 1 INVITE" in self._sent()[-1]
        assert cancelled == ["r3"]
        assert not self.server.ringing

    async def test_cancel_after_answer_or_for_unknown_calls(self) -> None:
        """CANCEL of an answered call is a no-op; an unknown one gets 481."""
        await self.server.handle_datagram(invite("r4", "*111", HA_NUMBER), GATEWAY)

        await self.server.handle_datagram(cancel("r4"), GATEWAY)
        assert self._sent()[-1].startswith("SIP/2.0 200 OK")
        assert "r4" in self.server.pending_acks

        await self.server.handle_datagram(cancel("nope"), GATEWAY)
        assert self._sent()[-1].startswith("SIP/2.0 481 ")

    async def test_stop_closes_rtp_sessions(self) -> None:
        """Stopping the server closes all call audio."""
        await self.server.handle_datagram(invite("c11", "*111", HA_NUMBER), GATEWAY)

        await self.server.stop()

        assert not self.server.rtp_sessions

    @staticmethod
    def _options(call_id: str, cseq: int) -> bytes:
        return sip(
            "OPTIONS sip:127.0.0.1 SIP/2.0",
            {
                "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z5",
                "From": f"<sip:gateway@{GATEWAY[0]}>;tag=o",
                "To": "<sip:127.0.0.1>",
                "Call-ID": call_id,
                "CSeq": f"{cseq} OPTIONS",
            },
        )


if __name__ == "__main__":
    unittest.main()
