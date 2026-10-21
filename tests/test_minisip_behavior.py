"""Behavioral tests for the MiniSIP server."""

import re
import unittest

from custom_components.sg_150.sip.minisip import (
    CallContext,
    MiniSIPServer,
    SIPDialog,
    md5_hex,
)
from tests.sip_messages import GATEWAY, HA_NUMBER, ack, bye, invite, sip
from tests.utils import FakeTransport


class MiniSIPBehaviorTests(unittest.IsolatedAsyncioTestCase):
    """Behavior-level tests for MiniSIP SIP flow."""

    async def test_register_with_valid_digest_registers_user(self) -> None:
        """A valid REGISTER digest should update the user registration."""
        server = MiniSIPServer(
            {"alice": "secret"},
            host="127.0.0.1",
            call_host="127.0.0.1",
            realm="example",
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
            {"alice": "secret"}, host="127.0.0.1", call_host="127.0.0.1", port=5070
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
        assert "Allow: REGISTER, INVITE, ACK, BYE, OPTIONS" in response

    async def test_options_with_old_cseq_is_rejected(self) -> None:
        """An out-of-order OPTIONS gets a 400 that is actually sent."""
        await self.server.handle_datagram(self._options("o2", 5), GATEWAY)
        await self.server.handle_datagram(self._options("o2", 1), GATEWAY)

        assert len(self._sent()) == 2
        assert self._sent()[-1].startswith("SIP/2.0 400 Bad Request")

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
