"""Behavioral tests for the MiniSIP server."""

import re
import unittest

from custom_components.sg_150.sip.minisip import CallContext, MiniSIPServer, md5_hex
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
        assert server.registrations["alice"]["addr"] == ("192.168.1.50", 5060)
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

        assert seen == ["call-123"]
        assert len(server.transport.sent) == 2
        assert server.transport.sent[0][0].startswith(b"SIP/2.0 180 Ringing")
        assert server.transport.sent[1][0].startswith(b"SIP/2.0 200 OK")
        assert "call-123" in server.active_calls
        assert server.active_calls["call-123"][0] == ("192.168.1.10", 5060)

    async def test_handle_bye_closes_call_and_returns_ok(self) -> None:
        """BYE should close the active call and answer with a success response."""
        server = MiniSIPServer(
            {"alice": "secret"},
            host="127.0.0.1",
            call_host="127.0.0.1",
        )
        server.transport = FakeTransport()
        server.active_calls["call-456"] = (
            ("192.168.1.10", 5060),
            "<sip:1001@192.168.1.10>",
            "<sip:2000@127.0.0.1>",
            "<sip:1001@192.168.1.10>",
            {},
        )

        await server.handle_bye(
            {"Call-ID": "call-456", "CSeq": "2 BYE"}, ("192.168.1.10", 5060)
        )

        assert "call-456" not in server.active_calls
        assert server.transport.sent
        assert server.transport.sent[0][0].startswith(b"SIP/2.0 200 OK")


if __name__ == "__main__":
    unittest.main()
