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
    Registered,
    match_device,
)
from custom_components.sg_150.sip.minisip import MiniSIPServer, md5_hex
from tests.utils import FakeTransport, load_devices

GATEWAY = ("192.168.1.10", 5060)
HA_HOST = "127.0.0.1"
SIP_USER = "gateway"
SIP_PASSWORD = "secret"  # noqa: S105
HA_NUMBER = "*2620"

INVITE_SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 192.168.1.10\r\n"
    "s=Siedle\r\n"
    "c=IN IP4 192.168.1.10\r\n"
    "t=0 0\r\n"
    "m=audio 4000 RTP/AVP 8\r\n"
    "a=rtpmap:8 PCMA/8000"
)


def sip(start_line: str, headers: dict[str, str], body: str = "") -> bytes:
    """Build a SIP datagram."""
    lines = [start_line, *(f"{k}: {v}" for k, v in headers.items())]
    lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


def invite(call_id: str, from_user: str, to_user: str) -> bytes:
    """Build an INVITE from the gateway."""
    return sip(
        f"INVITE sip:{to_user}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z1",
            "From": f"<sip:{from_user}@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{to_user}@{HA_HOST}>",
            "Call-ID": call_id,
            "CSeq": "1 INVITE",
            "Contact": f"<sip:{from_user}@{GATEWAY[0]}>",
            "Content-Type": "application/sdp",
        },
        INVITE_SDP,
    )


def ack(call_id: str) -> bytes:
    """Build the ACK the gateway sends after our 200 OK."""
    return sip(
        f"ACK sip:{HA_NUMBER}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z4",
            "From": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{HA_NUMBER}@{HA_HOST}>;tag=minisip",
            "Call-ID": call_id,
            "CSeq": "1 ACK",
        },
    )


def bye(call_id: str) -> bytes:
    """Build a BYE from the gateway."""
    return sip(
        f"BYE sip:{SIP_USER}@{HA_HOST} SIP/2.0",
        {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z2",
            "From": f"<sip:*111@{GATEWAY[0]}>;tag=gw",
            "To": f"<sip:{HA_NUMBER}@{HA_HOST}>;tag=minisip",
            "Call-ID": call_id,
            "CSeq": "2 BYE",
        },
    )


class GatewayLineTests(unittest.IsolatedAsyncioTestCase):
    """GatewayLine behaviour seen through SIP traffic."""

    def setUp(self) -> None:
        """Create a server, a line and an event recorder."""
        self.devices = load_devices()
        self.server = MiniSIPServer(
            {SIP_USER: SIP_PASSWORD}, host=HA_HOST, call_host=HA_HOST
        )
        self.transport = FakeTransport()
        self.server.transport = self.transport
        self.events: list[LineEvent] = []
        self.line = self._line(auto_answer=True)

    def _line(self, *, auto_answer: bool) -> GatewayLine:
        line = GatewayLine(
            self.server,
            user=SIP_USER,
            number=HA_NUMBER,
            auto_answer=auto_answer,
            devices=self.devices.values,
        )
        line.subscribe(self.events.append)
        return line

    async def _receive(self, data: bytes) -> None:
        await self.server.handle_datagram(data, GATEWAY)

    def _sent_status_lines(self) -> list[str]:
        return [data.decode().split("\r\n", 1)[0] for data, _ in self.transport.sent]

    async def _register(self) -> None:
        headers = {
            "Via": f"SIP/2.0/UDP {GATEWAY[0]}:{GATEWAY[1]};branch=z0",
            "From": f"<sip:{SIP_USER}@{HA_HOST}>;tag=r",
            "To": f"<sip:{SIP_USER}@{HA_HOST}>",
            "Call-ID": "register-1",
            "CSeq": "1 REGISTER",
            "Expires": "300",
        }
        await self._receive(sip(f"REGISTER sip:{HA_HOST} SIP/2.0", headers))
        challenge = self.transport.sent[-1][0].decode()
        nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
        opaque = re.search(r'opaque="([^"]+)"', challenge).group(1)

        uri = f"sip:{HA_HOST}"
        ha1 = md5_hex(f"{SIP_USER}::{SIP_PASSWORD}")
        ha2 = md5_hex(f"REGISTER:{uri}")
        response = md5_hex(f"{ha1}:{nonce}:00000001:c:auth:{ha2}")
        headers["CSeq"] = "2 REGISTER"
        headers["Authorization"] = (
            f'Digest username="{SIP_USER}", realm="", nonce="{nonce}", '
            f'uri="{uri}", response="{response}", algorithm=MD5, '
            f'qop=auth, nc=00000001, cnonce="c", opaque="{opaque}"'
        )
        await self._receive(sip(f"REGISTER sip:{HA_HOST} SIP/2.0", headers))

    async def test_registration_is_reported(self) -> None:
        """A successful REGISTER makes the line registered and emits Registered."""
        assert self.line.registration is None

        await self._register()

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

    async def test_call_requires_registration(self) -> None:
        """Calling before the gateway registered raises NotRegisteredError."""
        with pytest.raises(NotRegisteredError):
            await self.line.call("*111")

    async def _answer_outgoing(self, status: str) -> asyncio.Task:
        await self._register()
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
