"""Tests for GatewayLine, driven through raw SIP datagrams."""

import asyncio
import re
import unittest

import pytest

from custom_components.sg_150.line import (
    CallEnded,
    CallFailedError,
    CallStarted,
    GatewayLine,
    IncomingCall,
    LineEvent,
    NotRegisteredError,
    NotRingingError,
    Registered,
    match_device,
)
from custom_components.sg_150.sip.minisip import MiniSIPServer
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
    register,
    sip,
)
from tests.utils import FakeTransport, fake_rtp_endpoint, load_devices


class GatewayLineTests(unittest.IsolatedAsyncioTestCase):
    """GatewayLine behaviour seen through SIP traffic."""

    def setUp(self) -> None:
        """Create a server, a line and an event recorder."""
        self.devices = load_devices()
        self.server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD},
            host=HA_HOST,
            call_host=HA_HOST,
            rtp_endpoint=fake_rtp_endpoint,
        )
        self.transport = FakeTransport()
        self.server.transport = self.transport
        self.events: list[LineEvent] = []
        self.line = self._line(auto_answer=True)

    def _line(self, *, auto_answer: bool, **kwargs: object) -> GatewayLine:
        line = GatewayLine(
            self.server,
            user=SIP_USER,
            number=HA_NUMBER,
            auto_answer=auto_answer,
            devices=self.devices.values,
            **kwargs,
        )
        line.subscribe(self.events.append)
        return line

    async def _receive(self, data: bytes) -> None:
        await self.server.handle_datagram(data, GATEWAY)

    def _sent_status_lines(self) -> list[str]:
        return [data.decode().split("\r\n", 1)[0] for data, _ in self.transport.sent]

    async def test_registration_is_reported(self) -> None:
        """A successful REGISTER makes the line registered and emits Registered."""
        assert self.line.registration is None

        await register(self.server)

        assert self.line.registration is not None
        assert self.line.registration.addr == GATEWAY
        assert [type(e) for e in self.events] == [Registered]

    async def test_incoming_call_from_door_to_external_phone(self) -> None:
        """An answered call is matched to its door and phone, then ends on BYE."""
        await self._receive(invite("call-1", "*111", HA_NUMBER))
        assert [type(e) for e in self.events] == [IncomingCall]
        await self._receive(ack("call-1"))

        incoming, started = self.events
        assert isinstance(incoming, IncomingCall)
        assert incoming.answered
        assert incoming.call.caller.id == "door-front"
        assert incoming.call.callee.id == "pbx-external"
        assert isinstance(started, CallStarted)
        assert started.call.involves("door-front")
        assert list(self.line.calls) == ["call-1"]
        assert self._sent_status_lines() == ["SIP/2.0 180 Ringing", "SIP/2.0 200 OK"]

        await self._receive(bye("call-1"))

        assert isinstance(self.events[-1], CallEnded)
        assert self.events[-1].call.id == "call-1"
        assert not self.line.calls

    async def test_unmatched_incoming_call_has_no_devices(self) -> None:
        """Numbers that match no device leave caller and callee empty."""
        await self._receive(invite("call-2", "*999", "*9999"))

        incoming = self.events[0]
        assert isinstance(incoming, IncomingCall)
        assert incoming.call.caller is None
        assert incoming.call.callee is None

    async def test_incoming_call_rejected_without_auto_answer(self) -> None:
        """With auto answer off the call is announced, then rejected as busy."""
        self.server.on_incoming_call.clear()
        self.events.clear()
        self.line = self._line(auto_answer=False)

        await self._receive(invite("call-3", "*111", HA_NUMBER))

        assert len(self.events) == 1
        assert isinstance(self.events[0], IncomingCall)
        assert not self.events[0].answered
        assert self._sent_status_lines() == ["SIP/2.0 486 Busy Here"]
        assert not self.line.calls

    def _ring_along_line(self, ring_timeout: float = 60) -> GatewayLine:
        self.server.on_incoming_call.clear()
        self.events.clear()
        return self._line(auto_answer=False, ring_along=True, ring_timeout=ring_timeout)

    async def test_ring_along_call_rings_until_answered(self) -> None:
        """Without auto answer, ring-along keeps the call ringing for answer()."""
        self.line = self._ring_along_line()

        await self._receive(invite("call-5", "*111", HA_NUMBER))

        assert self._sent_status_lines() == ["SIP/2.0 180 Ringing"]
        incoming = self.events[0]
        assert isinstance(incoming, IncomingCall)
        assert not incoming.answered
        assert self.line.ringing["call-5"].involves("door-front")

        await self.line.answer("call-5")
        await self._receive(ack("call-5"))

        assert self._sent_status_lines()[-1] == "SIP/2.0 200 OK"
        assert not self.line.ringing
        assert isinstance(self.events[-1], CallStarted)
        assert self.line.calls["call-5"].rtp_session().codec == "PCMA"

    async def test_cancelled_ringing_call_cannot_be_answered(self) -> None:
        """A handset answering first (CANCEL) ends the ringing call."""
        self.line = self._ring_along_line()
        await self._receive(invite("call-6", "*111", HA_NUMBER))

        await self._receive(cancel("call-6"))

        assert not self.line.ringing
        with pytest.raises(NotRingingError):
            await self.line.answer("call-6")

    async def test_unanswered_ringing_call_is_rejected_after_the_timeout(self) -> None:
        """Nobody answering ends the call with 486 Busy Here."""
        self.line = self._ring_along_line(ring_timeout=0.01)
        await self._receive(invite("call-7", "*111", HA_NUMBER))

        await asyncio.sleep(0.05)

        assert self._sent_status_lines()[-1] == "SIP/2.0 486 Busy Here"
        assert not self.line.ringing

    async def test_stop_cancels_ring_timers(self) -> None:
        """Stopping the line forgets ringing calls without rejecting them."""
        self.line = self._ring_along_line(ring_timeout=0.01)
        await self._receive(invite("call-8", "*111", HA_NUMBER))

        await self.line.stop()
        await asyncio.sleep(0.05)

        assert self._sent_status_lines() == ["SIP/2.0 180 Ringing"]
        assert not self.line.ringing

    async def test_outgoing_offer_is_sendrecv_with_both_codecs(self) -> None:
        """We offer PCMA and PCMU, sendrecv, on the call's RTP port."""
        task = await self._answer_outgoing("SIP/2.0 200 OK")
        await task

        offer = next(
            data.decode()
            for data, _ in self.transport.sent
            if data.startswith(b"INVITE ")
        )
        assert "m=audio 5004 RTP/AVP 8 0\r\n" in offer
        assert "a=sendrecv" in offer
        assert "sendonly" not in offer

    async def test_failed_outgoing_call_frees_its_rtp_port(self) -> None:
        """A busy outgoing call closes its RTP session."""
        task = await self._answer_outgoing("SIP/2.0 486 Busy Here")
        with pytest.raises(CallFailedError):
            await task

        assert not self.server.rtp_sessions

    async def test_call_requires_registration(self) -> None:
        """Calling before the gateway registered raises NotRegisteredError."""
        with pytest.raises(NotRegisteredError):
            await self.line.call("*111")

    async def _answer_outgoing(self, status: str) -> asyncio.Task:
        await register(self.server)
        self.transport.sent.clear()
        task = asyncio.create_task(self.line.call("*111"))
        await asyncio.sleep(0)  # let the task send its INVITE
        request = self.transport.sent[0][0].decode()
        call_id = re.search(r"Call-ID: (.+)\r\n", request).group(1)
        await self._receive(
            sip(
                status,
                {
                    "Via": f"SIP/2.0/UDP {HA_HOST}:5060;branch=z3",
                    "From": f"<sip:{HA_NUMBER}@{HA_HOST}>",
                    "To": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
                    "Call-ID": call_id,
                    "CSeq": "1 INVITE",
                    "Contact": f"<sip:*111@{GATEWAY[0]}>",
                },
            )
        )
        return task

    async def test_outgoing_call_and_hangup(self) -> None:
        """An answered outgoing call is tracked until it is hung up."""
        call = await (await self._answer_outgoing("SIP/2.0 200 OK"))

        assert call.direction == "outgoing"
        assert call.caller.id == "pbx-external"
        assert call.callee.id == "door-front"
        assert isinstance(self.events[-1], CallStarted)
        assert self.line.calls[call.id] is call

        await call.hangup()

        assert self.transport.sent[-1][0].startswith(b"BYE ")
        assert isinstance(self.events[-1], CallEnded)
        assert not self.line.calls

    async def test_busy_outgoing_call_fails(self) -> None:
        """A busy response raises CallFailedError and tracks no call."""
        task = await self._answer_outgoing("SIP/2.0 486 Busy Here")

        with pytest.raises(CallFailedError):
            await task
        assert not self.line.calls

    async def test_failing_subscriber_does_not_break_the_line(self) -> None:
        """An exception in one subscriber still lets the others run."""

        def broken(_: LineEvent) -> None:
            raise RuntimeError

        self.line.subscribe(broken)
        seen: list[LineEvent] = []
        self.line.subscribe(seen.append)

        await self._receive(invite("call-4", "*111", HA_NUMBER))
        await self._receive(ack("call-4"))

        assert len(seen) == 2
        assert "call-4" in self.line.calls


class MatchDeviceTests(unittest.TestCase):
    """Matching SIP headers to gateway devices."""

    def setUp(self) -> None:
        """Load the fixture devices."""
        self.devices = list(load_devices().values())

    def test_matches_dialable_number(self) -> None:
        """The SIP user part is compared with prefix + extension."""
        device = match_device('"Front" <sip:*111@192.0.2.1>;tag=x', self.devices)

        assert device.id == "door-front"

    def test_matches_external_extension(self) -> None:
        """External PBX phones also match their external extension."""
        assert match_device("<sip:0620@192.0.2.1>", self.devices).id == "pbx-external"

    def test_matches_unique_bare_extension(self) -> None:
        """A bare extension matches when only one device has it."""
        assert match_device("<sip:12@192.0.2.1>", self.devices).id == "door-back"

    def test_no_match(self) -> None:
        """Unknown numbers and unparsable headers match nothing."""
        assert match_device("<sip:*999@192.0.2.1>", self.devices) is None
        assert match_device("garbage", self.devices) is None
