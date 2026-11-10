"""Behavioral tests for the MiniSIP server."""

import asyncio
import contextlib
import dataclasses
import re
import time
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
from tests.sip_messages import (
    GATEWAY,
    HA_HOST,
    HA_NUMBER,
    SIP_PASSWORD,
    SIP_USER,
    ack,
    bye,
    cancel,
    invite,
    invite_response,
    options,
    register,
    sip,
)
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
            local="<sip:2000@127.0.0.1>;tag=ha",
            remote="<sip:1001@192.168.1.10>;tag=gw",
            remote_target="sip:1001@192.168.1.10",
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
            trusted_hosts=[GATEWAY[0]],
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
        await self.server.handle_datagram(options("o1", 1), GATEWAY)

        response = self._sent()[-1]
        assert response.startswith("SIP/2.0 200 OK")
        assert "Allow: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS" in response

    async def test_options_with_old_cseq_is_rejected(self) -> None:
        """An out-of-order OPTIONS gets a 400 that is actually sent."""
        await self.server.handle_datagram(options("o2", 5), GATEWAY)
        await self.server.handle_datagram(options("o2", 1), GATEWAY)

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
            trusted_hosts=[GATEWAY[0]],
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
            trusted_hosts=[GATEWAY[0]],
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

        ringing, ok = self._sent()
        assert ok.startswith("SIP/2.0 200 OK")
        to_tag = re.search(r"\r\nTo: [^\r]*;tag=(\w+)", ok).group(1)
        assert f";tag={to_tag}\r\n" in ringing
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


STRANGER = ("192.0.2.99", 5060)


class MiniSIPSenderTests(unittest.IsolatedAsyncioTestCase):
    """Who may talk to the server, and what it does with malformed datagrams."""

    def setUp(self) -> None:
        """Create a server that trusts nobody until the gateway registers."""
        self.server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD},
            host=HA_HOST,
            call_host=HA_HOST,
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.server.transport = FakeTransport()
        self.incoming: list[str] = []

        async def on_incoming_call(context: CallContext) -> IncomingCallDecision:
            self.incoming.append(context.call_id)
            return IncomingCallDecision.ANSWER

        self.server.add_listener("on_incoming_call", on_incoming_call)

    def _sent(self) -> list[str]:
        return [data.decode() for data, _ in self.server.transport.sent]

    async def test_requests_from_an_unknown_address_are_dropped(self) -> None:
        """No reply, no call and no RTP session for an unregistered sender."""
        await register(self.server)
        sent_before = len(self.server.transport.sent)

        for data in (
            invite("x1", "*111", HA_NUMBER),
            ack("x1"),
            bye("x1"),
            cancel("x1"),
            options("x2", 1),
        ):
            await self.server.handle_datagram(data, STRANGER)

        assert len(self.server.transport.sent) == sent_before
        assert not self.incoming
        assert not self.server.rtp_sessions
        assert not self.server.active_calls

    async def test_register_from_an_unknown_address_is_challenged(self) -> None:
        """REGISTER carries its own authentication, so anyone gets a challenge."""
        await register(self.server)
        await self.server.handle_datagram(
            sip(
                f"REGISTER sip:{HA_HOST} SIP/2.0",
                {
                    "Via": f"SIP/2.0/UDP {STRANGER[0]}:{STRANGER[1]};branch=z9",
                    "From": f"<sip:{SIP_USER}@{HA_HOST}>;tag=s",
                    "To": f"<sip:{SIP_USER}@{HA_HOST}>",
                    "Call-ID": "register-stranger",
                    "CSeq": "1 REGISTER",
                },
            ),
            STRANGER,
        )

        assert self._sent()[-1].startswith("SIP/2.0 401 Unauthorized")

    async def test_registered_ip_is_trusted_on_any_port(self) -> None:
        """The gateway may send from another source port than it registered from."""
        await register(self.server)

        await self.server.handle_datagram(
            invite("c1", "*111", HA_NUMBER), (GATEWAY[0], GATEWAY[1] + 1)
        )

        assert self.incoming == ["c1"]
        assert self._sent()[-1].startswith("SIP/2.0 200 OK")

    async def test_configured_host_is_trusted_before_it_registers(self) -> None:
        """After a restart, the gateway's calls arrive before its next REGISTER."""
        server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD},
            host=HA_HOST,
            call_host=HA_HOST,
            rtp_endpoint=fake_rtp_endpoint,
            trusted_hosts=[GATEWAY[0]],
        )

        assert server.is_trusted(GATEWAY)
        assert not server.is_trusted(STRANGER)

    async def test_trusted_host_names_are_resolved_on_start(self) -> None:
        """A host name is resolved once; a failure only logs a warning."""
        server = MiniSIPServer({}, trusted_hosts=["gateway.local", "missing.local"])
        loop = asyncio.get_running_loop()

        async def getaddrinfo(host: str, *_: object, **__: object) -> list:
            if host == "missing.local":
                msg = "Name or service not known"
                raise OSError(msg)
            return [(2, 2, 17, "", ("192.0.2.42", 0))]

        with (
            patch.object(loop, "getaddrinfo", getaddrinfo),
            self.assertLogs("sip-server", "WARNING") as logs,
        ):
            await server._resolve_trusted_hosts()  # noqa: SLF001

        assert server.is_trusted(("192.0.2.42", 5060))
        assert "missing.local" in logs.output[0]

    async def test_responses_from_an_unknown_address_are_dropped(self) -> None:
        """A forged response cannot answer our pending INVITE."""
        await register(self.server)
        self.server.transport.sent.clear()
        task = asyncio.create_task(
            self.server.send_invite(GATEWAY, HA_NUMBER, "*111", timeout=1)
        )
        await asyncio.sleep(0)
        call_id = _header(self._sent()[0], "Call-ID")

        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), STRANGER
        )
        await asyncio.sleep(0)
        assert not task.done()

        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )
        assert (await task)[0] == call_id

    async def test_keepalives_and_garbage_get_no_reply(self) -> None:
        """Only SIP requests and responses are handled; nothing else is answered."""
        await register(self.server)
        sent_before = len(self.server.transport.sent)

        for data in (b"", b"\r\n", b"\r\n\r\n", b"hello", b"GET / HTTP/1.1\r\n\r\n"):
            await self.server.handle_datagram(data, GATEWAY)

        assert len(self.server.transport.sent) == sent_before

    async def test_request_without_required_headers_gets_bad_request(self) -> None:
        """A request missing Call-ID, CSeq, Via, From or To is answered with 400."""
        await register(self.server)

        await self.server.handle_datagram(
            sip(
                f"INVITE sip:{HA_NUMBER}@{HA_HOST} SIP/2.0",
                {"Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z1"},
            ),
            GATEWAY,
        )

        assert self._sent()[-1].startswith("SIP/2.0 400 Bad Request")
        assert not self.incoming

    async def test_incomplete_ack_gets_no_reply(self) -> None:
        """ACK is never answered, not even when it is malformed."""
        await register(self.server)
        sent_before = len(self.server.transport.sent)

        await self.server.handle_datagram(
            sip(f"ACK sip:{HA_NUMBER}@{HA_HOST} SIP/2.0", {}), GATEWAY
        )

        assert len(self.server.transport.sent) == sent_before

    async def test_failing_incoming_call_listener_answers_server_error(self) -> None:
        """An exception in a listener still answers the INVITE."""
        await register(self.server)

        async def broken(_: CallContext) -> IncomingCallDecision:
            raise RuntimeError

        self.server.add_listener("on_incoming_call", broken)

        with self.assertLogs("sip-server", "ERROR"):
            await self.server.handle_datagram(invite("c2", "*111", HA_NUMBER), GATEWAY)

        assert self._sent()[-1].startswith("SIP/2.0 500 Server Internal Error")
        assert not self.server.rtp_sessions

    async def test_handler_errors_are_logged(self) -> None:
        """An exception while handling a datagram is logged, not raised."""
        await register(self.server)

        with (
            patch.object(self.server, "handle_options", side_effect=RuntimeError),
            self.assertLogs("sip-server", "ERROR") as logs,
        ):
            await self.server.handle_datagram(options("o1", 1), GATEWAY)

        assert "Error handling SIP datagram" in logs.output[0]

    async def test_stop_cancels_handlers_in_flight(self) -> None:
        """Datagram handler tasks are tracked and cancelled by stop()."""
        await register(self.server)
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def slow_options(*_: object) -> None:
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        with patch.object(self.server, "handle_options", slow_options):
            self.server.datagram_received(options("o1", 1), GATEWAY)
            await started.wait()
            assert len(self.server._tasks) == 1  # noqa: SLF001

            await self.server.stop()

        assert cancelled.is_set()
        assert not self.server._tasks  # noqa: SLF001

    async def test_nothing_is_sent_after_stop(self) -> None:
        """A handler that resumes after stop() does not touch the closed transport."""
        await register(self.server)

        async def stop_meanwhile(_: CallContext) -> IncomingCallDecision:
            await self.server.stop()
            return IncomingCallDecision.RING

        self.server.on_incoming_call[:] = [stop_meanwhile]

        await self.server.handle_datagram(invite("c3", "*111", HA_NUMBER), GATEWAY)

        assert self.server.transport is None


def _header(message: str, name: str) -> str:
    return re.search(rf"\r\n{name}: ([^\r]*)", message).group(1)


def _response_to(request: str, status: str, *, to_tag: str | None = None) -> bytes:
    """Build the gateway's response to one of our requests."""
    headers = {
        name: _header(request, name)
        for name in ("Via", "From", "To", "Call-ID", "CSeq")
    }
    if to_tag:
        headers["To"] += f";tag={to_tag}"
    return sip(status, headers)


class _MiniSIPCallTestCase(unittest.IsolatedAsyncioTestCase):
    """A server on a non-default port with helpers for calls through it."""

    def setUp(self) -> None:
        """Create a server on a non-default port that trusts the gateway."""
        self.server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD},
            host=HA_HOST,
            call_host=HA_HOST,
            port=5070,
            rtp_endpoint=fake_rtp_endpoint,
            trusted_hosts=[GATEWAY[0]],
        )
        self.server.transport = FakeTransport()

    def _sent(self) -> list[str]:
        return [data.decode() for data, _ in self.server.transport.sent]

    def _requests(self, method: str) -> list[str]:
        return [m for m in self._sent() if m.startswith(f"{method} ")]

    async def _dial(
        self, give_up_after: float = 1, ring_for: float = 1
    ) -> tuple[asyncio.Task, str]:
        """Start an outgoing call to the front door and return its call id."""
        task = asyncio.create_task(
            self.server.send_invite(
                GATEWAY,
                HA_NUMBER,
                "*111",
                timeout=give_up_after,
                ring_timeout=ring_for,
            )
        )
        while not self._requests("INVITE"):  # noqa: ASYNC110
            await asyncio.sleep(0)
        return task, _header(self._requests("INVITE")[0], "Call-ID")

    async def _answer_incoming(self, call_id: str) -> None:
        await self.server.handle_datagram(invite(call_id, "*111", HA_NUMBER), GATEWAY)
        await self.server.handle_datagram(ack(call_id), GATEWAY)


class MiniSIPDialogTests(_MiniSIPCallTestCase):
    """Response handling and the requests we send within a call."""

    async def test_responses_arriving_together_establish_the_call(self) -> None:
        """A 180 directly followed by a 200 must not lose the 200."""
        task, call_id = await self._dial()

        await self.server.handle_datagram(
            invite_response("SIP/2.0 180 Ringing", call_id), GATEWAY
        )
        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )

        assert (await task)[0] == call_id
        assert call_id in self.server.active_calls
        assert not self.server.pending_invites

    async def test_other_provisional_responses_keep_waiting(self) -> None:
        """183 Session Progress is provisional, not a failure."""
        task, call_id = await self._dial()

        await self.server.handle_datagram(
            invite_response("SIP/2.0 183 Session Progress", call_id), GATEWAY
        )
        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )

        assert (await task)[0] == call_id

    async def test_cancelled_dial_forgets_its_response_queue(self) -> None:
        """Cancelling the calling task removes its pending INVITE."""
        task, _ = await self._dial()

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        assert not self.server.pending_invites
        assert not self.server.rtp_sessions

    async def test_outgoing_invite_is_well_formed(self) -> None:
        """Our INVITE has a From tag, an RFC 3261 branch and a Contact with port."""
        task, _ = await self._dial(give_up_after=0.01)
        await task

        request = self._requests("INVITE")[0]
        assert request.startswith(f"INVITE sip:*111@{GATEWAY[0]} SIP/2.0\r\n")
        assert re.fullmatch(
            rf"<sip:{re.escape(HA_NUMBER)}@{HA_HOST}>;tag=\w+",
            _header(request, "From"),
        )
        assert _header(request, "To") == f"<sip:*111@{GATEWAY[0]}>"
        assert ";branch=z9hG4bK" in _header(request, "Via")
        assert _header(request, "Contact") == f"<sip:{HA_NUMBER}@{HA_HOST}:5070>"

    async def test_outgoing_call_requests_use_the_dialog(self) -> None:
        """ACK, INFO and BYE go to the remote Contact with our tag and theirs."""
        task, call_id = await self._dial()
        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )
        await task
        await self.server.send_sip_info_dtmf(call_id, "1", "250")
        await self.server.send_bye(call_id)

        from_header = _header(self._requests("INVITE")[0], "From")
        for method, cseq in (("ACK", "1 ACK"), ("INFO", "2 INFO"), ("BYE", "3 BYE")):
            (request,) = self._requests(method)
            assert request.startswith(f"{method} sip:*111@{GATEWAY[0]} SIP/2.0\r\n")
            assert _header(request, "From") == from_header
            assert _header(request, "To") == f"<sip:*111@{GATEWAY[0]}>;tag=gw"
            assert _header(request, "CSeq") == cseq
            assert _header(request, "Contact") == f"<sip:{HA_NUMBER}@{HA_HOST}:5070>"

    async def test_failed_outgoing_call_is_acked_in_the_invite_transaction(
        self,
    ) -> None:
        """A non-2xx final response is ACKed with the INVITE's branch and URI."""
        task, call_id = await self._dial()

        await self.server.handle_datagram(
            invite_response("SIP/2.0 486 Busy Here", call_id, contact=None), GATEWAY
        )

        assert await task == (None, None)
        invite_request = self._requests("INVITE")[0]
        (ack_request,) = self._requests("ACK")
        assert ack_request.startswith(f"ACK sip:*111@{GATEWAY[0]} SIP/2.0\r\n")
        assert _header(ack_request, "Via") == _header(invite_request, "Via")
        assert _header(ack_request, "From") == _header(invite_request, "From")
        assert _header(ack_request, "To") == f"<sip:*111@{GATEWAY[0]}>;tag=gw"
        assert _header(ack_request, "CSeq") == "1 ACK"

    async def test_incoming_call_bye_uses_the_dialog(self) -> None:
        """Our BYE goes to the caller's Contact, with From and To swapped."""
        await self.server.handle_datagram(invite("c1", "*111", HA_NUMBER), GATEWAY)
        await self.server.handle_datagram(ack("c1"), GATEWAY)
        ok = self._sent()[-1]

        await self.server.send_bye("c1")

        (request,) = self._requests("BYE")
        assert request.startswith(f"BYE sip:*111@{GATEWAY[0]} SIP/2.0\r\n")
        assert _header(request, "From") == _header(ok, "To")
        assert _header(request, "From").startswith(f"<sip:{HA_NUMBER}@{HA_HOST}>;tag=")
        assert _header(request, "To") == f"<sip:*111@{GATEWAY[0]}>;tag=gw"
        assert _header(request, "Contact") == f"<sip:{HA_NUMBER}@{HA_HOST}:5070>"
        assert ";branch=z9hG4bK" in _header(request, "Via")

    async def test_incoming_calls_get_their_own_to_tag(self) -> None:
        """Each incoming call is answered with a fresh To tag."""
        await self.server.handle_datagram(invite("c1", "*111", HA_NUMBER), GATEWAY)
        await self.server.handle_datagram(invite("c2", "*111", HA_NUMBER), GATEWAY)

        tags = {
            _header(m, "To").rsplit(";tag=", 1)[1]
            for m in self._sent()
            if m.startswith("SIP/2.0 200 OK")
        }
        assert len(tags) == 2

    async def test_remote_target_falls_back_to_the_from_uri(self) -> None:
        """Without a Contact in the INVITE, requests go to the caller's From URI."""
        data = invite("c1", "*111", HA_NUMBER).replace(
            f"Contact: <sip:*111@{GATEWAY[0]}>\r\n".encode(), b""
        )
        await self.server.handle_datagram(data, GATEWAY)
        await self.server.handle_datagram(ack("c1"), GATEWAY)

        assert self.server.active_calls["c1"].remote_target == f"sip:*111@{GATEWAY[0]}"


class MiniSIPLossTests(_MiniSIPCallTestCase):
    """Timeouts and resending, with RFC 3261 timers shortened to 10 ms."""

    def setUp(self) -> None:
        """Shorten T1 and T2 and record ended calls."""
        super().setUp()
        self.enterContext(patch.multiple(minisip, TIMER_T1=0.01, TIMER_T2=0.02))
        self.ended: list[str] = []

        async def on_ended(dialog: SIPDialog) -> None:
            self.ended.append(dialog.call_id)

        self.server.add_listener("on_call_ended", on_ended)

    async def test_lost_bye_is_resent_until_answered(self) -> None:
        """The call ends at once; the BYE is resent until its 200 OK arrives."""
        await self._answer_incoming("c1")

        await self.server.send_bye("c1")
        assert self.ended == ["c1"]
        await asyncio.sleep(0.05)
        byes = self._requests("BYE")
        assert len(byes) >= 3
        assert len(set(byes)) == 1

        await self.server.handle_datagram(
            _response_to(byes[0], "SIP/2.0 200 OK"), GATEWAY
        )
        await asyncio.sleep(0.05)
        assert len(self._requests("BYE")) == len(byes)

    async def test_unanswered_bye_gives_up_after_64_t1(self) -> None:
        """Resending stops after 64 * T1 without a response."""
        with patch.multiple(minisip, TIMER_T1=0.001, TIMER_T2=0.004):
            await self._answer_incoming("c1")
            await self.server.send_bye("c1")
            await asyncio.sleep(0.2)
            sent = len(self._requests("BYE"))
            await asyncio.sleep(0.05)

        assert len(self._requests("BYE")) == sent
        assert not self.server._unanswered  # noqa: SLF001
        assert not self.server._tasks  # noqa: SLF001

    async def test_info_is_resent_until_answered(self) -> None:
        """A DTMF INFO is resent like a BYE."""
        await self._answer_incoming("c1")

        await self.server.send_sip_info_dtmf("c1", "1", "250")
        await asyncio.sleep(0.05)
        infos = self._requests("INFO")
        await self.server.handle_datagram(
            _response_to(infos[0], "SIP/2.0 200 OK"), GATEWAY
        )
        await asyncio.sleep(0.05)

        assert len(infos) >= 2
        assert len(self._requests("INFO")) == len(infos)
        assert "c1" in self.server.active_calls

    async def test_silent_call_is_hung_up(self) -> None:
        """No RTP for rtp_timeout seconds ends the call with a BYE."""
        self.server.rtp_timeout = 0.05
        await self._answer_incoming("c1")

        await asyncio.sleep(0.15)

        assert self.ended == ["c1"]
        assert len(set(self._requests("BYE"))) == 1
        assert not self.server.rtp_sessions

    async def test_invite_is_resent_until_the_first_response(self) -> None:
        """The INVITE is resent from T1 until any response arrives."""
        task, call_id = await self._dial()
        await asyncio.sleep(0.05)
        invites = self._requests("INVITE")
        assert len(invites) >= 3
        assert len(set(invites)) == 1

        await self.server.handle_datagram(
            invite_response("SIP/2.0 100 Trying", call_id), GATEWAY
        )
        await asyncio.sleep(0.05)
        assert len(self._requests("INVITE")) == len(invites)

        task.cancel()

    async def test_unanswered_invite_gives_up_without_cancel(self) -> None:
        """Without any response there is nothing to cancel."""
        task, _ = await self._dial(give_up_after=0.05)

        assert await task == (None, None)
        assert not self._requests("CANCEL")
        assert not self.server.rtp_sessions

    async def test_long_ringing_call_can_still_be_answered(self) -> None:
        """After 180 the ring timeout applies, not the first-response timeout."""
        task, call_id = await self._dial(give_up_after=0.03, ring_for=1)
        await self.server.handle_datagram(
            invite_response("SIP/2.0 180 Ringing", call_id), GATEWAY
        )
        await asyncio.sleep(0.06)

        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )

        assert (await task)[0] == call_id

    async def test_ring_timeout_cancels_the_invite_and_acks_the_487(self) -> None:
        """A call nobody answers is cancelled; the 487 that follows is ACKed."""
        task, call_id = await self._dial(ring_for=0.03)
        await self.server.handle_datagram(
            invite_response("SIP/2.0 180 Ringing", call_id), GATEWAY
        )

        assert await task == (None, None)
        invite_request = self._requests("INVITE")[0]
        cancel_request = self._requests("CANCEL")[0]
        assert cancel_request.startswith(f"CANCEL sip:*111@{GATEWAY[0]} SIP/2.0\r\n")
        for name in ("Via", "From", "To", "Call-ID"):
            assert _header(cancel_request, name) == _header(invite_request, name)
        assert _header(cancel_request, "CSeq") == "1 CANCEL"

        await self.server.handle_datagram(
            _response_to(cancel_request, "SIP/2.0 200 OK"), GATEWAY
        )
        await self.server.handle_datagram(
            invite_response("SIP/2.0 487 Request Terminated", call_id), GATEWAY
        )
        await asyncio.sleep(0.05)

        cancels = len(self._requests("CANCEL"))
        (ack_request,) = self._requests("ACK")
        assert _header(ack_request, "Via") == _header(invite_request, "Via")
        assert _header(ack_request, "CSeq") == "1 ACK"
        await asyncio.sleep(0.05)
        assert len(self._requests("CANCEL")) == cancels

    async def test_cancelled_dial_sends_cancel(self) -> None:
        """Cancelling the calling task while it rings cancels the INVITE."""
        task, call_id = await self._dial()
        await self.server.handle_datagram(
            invite_response("SIP/2.0 180 Ringing", call_id), GATEWAY
        )

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        assert len(self._requests("CANCEL")) == 1

    async def test_late_answer_is_acked_and_hung_up(self) -> None:
        """A 200 OK after we gave up gets an ACK and a BYE, and no call."""
        task, call_id = await self._dial(ring_for=0.01)
        await self.server.handle_datagram(
            invite_response("SIP/2.0 180 Ringing", call_id), GATEWAY
        )
        await task

        for _ in range(2):  # the second 200 OK is a retransmission
            await self.server.handle_datagram(
                invite_response("SIP/2.0 200 OK", call_id), GATEWAY
            )

        acks = self._requests("ACK")
        assert len(acks) == 2
        assert acks[0] == acks[1]
        assert len(set(self._requests("BYE"))) == 1
        assert call_id not in self.server.active_calls
        assert not self.ended

    async def test_retransmitted_2xx_is_acked_again(self) -> None:
        """If our ACK got lost, the gateway resends the 200 OK: ACK it again."""
        task, call_id = await self._dial()
        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )
        await task

        await self.server.handle_datagram(
            invite_response("SIP/2.0 200 OK", call_id), GATEWAY
        )

        acks = self._requests("ACK")
        assert len(acks) == 2
        assert acks[0] == acks[1]

    async def test_stop_rejects_hangs_up_and_cancels(self) -> None:
        """stop() rejects ringing calls, ends active ones and cancels our INVITEs."""

        async def ring(_: CallContext) -> IncomingCallDecision:
            return IncomingCallDecision.RING

        await self._answer_incoming("active")
        self.server.add_listener("on_incoming_call", ring)
        await self.server.handle_datagram(invite("ringing", "*111", HA_NUMBER), GATEWAY)
        task, call_id = await self._dial()
        await self.server.handle_datagram(
            invite_response("SIP/2.0 180 Ringing", call_id), GATEWAY
        )
        transport = self.server.transport

        await self.server.stop()

        sent = [data.decode() for data, _ in transport.sent]
        assert any(
            m.startswith("SIP/2.0 486 ") and "Call-ID: ringing\r\n" in m for m in sent
        )
        assert sum(m.startswith("BYE ") for m in sent) == 1
        assert sum(m.startswith("CANCEL ") for m in sent) == 1
        assert self.ended == ["active"]
        assert await task == (None, None)
        assert not self.server.rtp_sessions
        assert not self.server._tasks  # noqa: SLF001


class MiniSIPRegistrationTests(unittest.IsolatedAsyncioTestCase):
    """Digest challenges and the lifetime of registrations."""

    def setUp(self) -> None:
        """Create a server for the gateway user and record registrations."""
        self.server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD},
            host=HA_HOST,
            call_host=HA_HOST,
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.server.transport = FakeTransport()
        self.registered: list[object] = []

        async def on_register(_: str, registration: object) -> None:
            self.registered.append(registration)

        self.server.add_listener("on_register", on_register)

    def _last_sent(self) -> str:
        return self.server.transport.sent[-1][0].decode()

    async def test_replayed_register_is_rejected(self) -> None:
        """A captured REGISTER cannot move the registration to another address."""
        data = await register(self.server)

        await self.server.handle_datagram(data, STRANGER)

        assert self._last_sent().startswith("SIP/2.0 401 Unauthorized")
        assert self.server.registrations[SIP_USER].addr == GATEWAY

    async def test_expired_challenge_is_rejected(self) -> None:
        """A nonce older than NONCE_LIFETIME no longer authenticates."""
        with patch.object(minisip, "NONCE_LIFETIME", -1):
            await register(self.server)

        assert self._last_sent().startswith("SIP/2.0 401 Unauthorized")
        assert SIP_USER not in self.server.registrations

    async def test_outstanding_challenges_are_capped_and_expire(self) -> None:
        """Unanswered challenges neither pile up nor live forever."""
        for _ in range(minisip.MAX_NONCES + 10):
            self.server.generate_nonce()
        assert len(self.server._nonces) == minisip.MAX_NONCES  # noqa: SLF001

        with patch.object(minisip, "NONCE_LIFETIME", -1):
            await self.server._expire()  # noqa: SLF001

        assert not self.server._nonces  # noqa: SLF001

    async def test_expires_zero_unregisters(self) -> None:
        """REGISTER with Expires: 0 removes the registration at once."""
        await register(self.server)

        await register(self.server, call_id="register-2", Expires="0")

        assert SIP_USER not in self.server.registrations
        assert self.registered[-1] is None
        assert self._last_sent().startswith("SIP/2.0 200 OK")
        assert "\r\nExpires: 0\r\n" in self._last_sent()

    async def test_contact_expires_takes_precedence(self) -> None:
        """An expires parameter on Contact wins over the Expires header."""
        await register(
            self.server,
            Contact=f"<sip:{SIP_USER}@{GATEWAY[0]}>;expires=120",
            Expires="300",
        )

        assert "\r\nExpires: 120\r\n" in self._last_sent()

        await register(
            self.server,
            call_id="register-2",
            Contact=f"<sip:{SIP_USER}@{GATEWAY[0]}>;expires=0",
        )
        assert SIP_USER not in self.server.registrations

    async def test_expiry_follows_the_monotonic_clock(self) -> None:
        """A wall-clock jump does not expire a registration; the deadline does."""
        await register(self.server)

        with patch.object(minisip.time, "time", return_value=time.time() + 10**6):
            await self.server._expire()  # noqa: SLF001
        assert SIP_USER in self.server.registrations

        self.server.registrations[SIP_USER] = dataclasses.replace(
            self.server.registrations[SIP_USER], deadline=time.monotonic() - 1
        )
        await self.server._expire()  # noqa: SLF001
        assert SIP_USER not in self.server.registrations
        assert self.registered[-1] is None


if __name__ == "__main__":
    unittest.main()
