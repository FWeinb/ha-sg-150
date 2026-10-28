"""
The SIP line between Home Assistant and the Smart Gateway.

GatewayLine is the only module that talks to MiniSIPServer. It knows which SIP
user is the gateway, which number Home Assistant calls from, whether incoming
calls are answered, and which SG150Device is on either end of a call.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from .const import LOGGER
from .sip.minisip import IncomingCallDecision, sip_user

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from .sip.minisip import CallContext, MiniSIPServer, SIPDialog, SIPRegistration
    from .sip.rtp import RtpSession
    from .types import SG150Device

# A ringing call nobody answers is rejected as busy after this many seconds.
RING_TIMEOUT = 60

type Direction = Literal["incoming", "outgoing"]


class LineError(Exception):
    """Base class for GatewayLine errors."""


class NotRegisteredError(LineError):
    """The gateway is not registered, so no call can be placed."""


class CallFailedError(LineError):
    """The gateway did not accept the call."""


class NotRingingError(LineError):
    """The call to answer is not ringing (any more)."""


@dataclass(frozen=True, eq=False)
class Call:
    """A call on the line, with the devices on either end if known."""

    id: str
    direction: Direction
    from_header: str
    to_header: str
    addr: tuple[str, int]
    caller: SG150Device | None
    callee: SG150Device | None
    _server: MiniSIPServer = field(repr=False)

    def involves(self, device_id: str) -> bool:
        """Return whether the device is the caller or the callee."""
        return any(
            device is not None and device.id == device_id
            for device in (self.caller, self.callee)
        )

    async def hangup(self) -> None:
        """End the call."""
        await self._server.send_bye(self.id)

    async def send_dtmf(self, signal: str, duration: str = "100") -> None:
        """Send a DTMF signal via SIP INFO."""
        await self._server.send_sip_info_dtmf(self.id, signal, duration)

    async def play(self, mime_type: str, audio_data: bytes) -> None:
        """Play audio into the call."""
        await self._server.play_audio(self.id, mime_type, audio_data)

    def rtp_session(self) -> RtpSession:
        """Return the audio stream of the established call."""
        return self._server.rtp_session(self.id)


@dataclass(frozen=True)
class Registered:
    """The gateway registered or refreshed its registration."""

    registration: SIPRegistration


@dataclass(frozen=True)
class Unregistered:
    """The gateway registration expired."""


@dataclass(frozen=True)
class IncomingCall:
    """The gateway is calling, before the call is answered or rejected."""

    call: Call
    answered: bool


@dataclass(frozen=True)
class CallStarted:
    """A call was established."""

    call: Call


@dataclass(frozen=True)
class CallEnded:
    """A call ended, from either side."""

    call: Call


type LineEvent = Registered | Unregistered | IncomingCall | CallStarted | CallEnded


def match_device(header: str, devices: Iterable[SG150Device]) -> SG150Device | None:
    """
    Find the device whose call number appears in a SIP From/To header.

    The SIP user part is compared against each device's dialable call number and
    the external PBX extension. If nothing matches exactly, a bare extension is
    accepted when exactly one device has it.
    """
    user = sip_user(header)
    if user is None:
        return None

    endpoints = [
        (device, device.phone_endpoint)
        for device in devices
        if device.phone_endpoint is not None
    ]
    for device, endpoint in endpoints:
        numbers = {
            endpoint.callNumber.dialable,
            endpoint.pbxSystem.externalExtension.dialable,
        }
        if user in numbers - {""}:
            return device

    by_extension = [
        device
        for device, endpoint in endpoints
        if endpoint.callNumber.extension == user
    ]
    return by_extension[0] if len(by_extension) == 1 else None


class GatewayLine:
    """The SIP line the Smart Gateway registers on."""

    def __init__(  # noqa: PLR0913
        self,
        server: MiniSIPServer,
        *,
        user: str,
        number: str,
        auto_answer: bool,
        devices: Callable[[], Iterable[SG150Device]],
        ring_along: bool = False,
        ring_timeout: float = RING_TIMEOUT,
    ) -> None:
        """
        Create a line in front of `server`.

        user: the SIP user the gateway registers as.
        number: the number Home Assistant calls from.
        auto_answer: answer incoming calls (True) or not (False).
        devices: returns the current gateway devices, used to match calls.
        ring_along: without auto answer, let incoming calls ring until answer()
            is called, instead of rejecting them as busy straight away. Calls
            nobody answers are rejected as busy after `ring_timeout` seconds.
        """
        self._server = server
        self.user = user
        self._number = number
        self._auto_answer = auto_answer
        self._ring_along = ring_along
        self._ring_timeout = ring_timeout
        self._devices = devices
        self._calls: dict[str, Call] = {}
        self._ringing: dict[str, Call] = {}
        self._ring_timers: dict[str, asyncio.TimerHandle] = {}
        self._tasks: set[asyncio.Task] = set()
        self._subscribers: list[Callable[[LineEvent], None]] = []

        server.add_listener("on_register", self._on_register)
        server.add_listener("on_incoming_call", self._on_incoming_call)
        server.add_listener("on_call_established", self._on_call_established)
        server.add_listener("on_call_ended", self._on_call_ended)
        server.add_listener("on_call_cancelled", self._on_call_cancelled)

    @property
    def registration(self) -> SIPRegistration | None:
        """Return where and until when the gateway is registered, if it is."""
        return self._server.registrations.get(self.user)

    @property
    def calls(self) -> Mapping[str, Call]:
        """Return the established calls by call id."""
        return self._calls

    @property
    def ringing(self) -> Mapping[str, Call]:
        """Return the incoming calls waiting for answer(), by call id."""
        return self._ringing

    async def start(self) -> None:
        """Start listening for SIP traffic."""
        await self._server.start()

    async def stop(self) -> None:
        """Stop listening for SIP traffic."""
        for call_id in list(self._ringing):
            self._stop_ringing(call_id)
        await self._server.stop()

    async def answer(self, call_id: str) -> None:
        """
        Answer a ringing incoming call.

        Raises NotRingingError if it is not ringing, for example because a
        handset answered first. The call starts once the gateway ACKs.
        """
        if self._stop_ringing(call_id) is None:
            msg = f"Call {call_id} is not ringing"
            raise NotRingingError(msg)
        await self._server.answer_call(call_id)

    def _stop_ringing(self, call_id: str) -> Call | None:
        if (timer := self._ring_timers.pop(call_id, None)) is not None:
            timer.cancel()
        return self._ringing.pop(call_id, None)

    def _on_ring_timeout(self, call_id: str) -> None:
        task = asyncio.create_task(self._reject_unanswered(call_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _reject_unanswered(self, call_id: str) -> None:
        if self._stop_ringing(call_id) is not None:
            LOGGER.debug("Nobody answered call %s, rejecting it", call_id)
            await self._server.reject_call(call_id)

    def subscribe(self, callback: Callable[[LineEvent], None]) -> Callable[[], None]:
        """
        Call `callback` with every LineEvent until the returned function is called.

        Callbacks run synchronously in the event loop, in subscription order.
        """
        self._subscribers.append(callback)

        def unsubscribe() -> None:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

        return unsubscribe

    async def call(self, to: str) -> Call:
        """
        Call `to` through the gateway and return the established call.

        Raises NotRegisteredError if the gateway is not registered and
        CallFailedError if the call is rejected, busy or times out.
        """
        registration = self.registration
        if registration is None:
            msg = "Not Connected"
            raise NotRegisteredError(msg)

        call_id, _ = await self._server.send_invite(
            target_addr=registration.addr, from_user=self._number, to_user=to
        )
        call = self._calls.get(call_id) if call_id else None
        if call is None:
            msg = f"Could not start call to {to}"
            raise CallFailedError(msg)
        return call

    def _emit(self, event: LineEvent) -> None:
        for callback in list(self._subscribers):
            try:
                callback(event)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Error in GatewayLine subscriber for %s", event)

    def _new_call(
        self,
        call_id: str,
        direction: Direction,
        from_header: str,
        to_header: str,
        addr: tuple[str, int],
    ) -> Call:
        devices = list(self._devices())
        call = Call(
            id=call_id,
            direction=direction,
            from_header=from_header,
            to_header=to_header,
            addr=addr,
            caller=match_device(from_header, devices),
            callee=match_device(to_header, devices),
            _server=self._server,
        )
        if call.caller is None or call.callee is None:
            LOGGER.warning(
                "Could not match all devices of %s call %s (From: %s, To: %s)",
                direction,
                call_id,
                from_header,
                to_header,
            )
        return call

    async def _on_register(
        self, user: str, registration: SIPRegistration | None
    ) -> None:
        if user != self.user:
            return
        self._emit(Registered(registration) if registration else Unregistered())

    async def _on_incoming_call(self, context: CallContext) -> bool:
        call = self._new_call(
            context.call_id,
            "incoming",
            context.called_from,
            context.called_to,
            context.addr,
        )
        if self._auto_answer:
            decision = IncomingCallDecision.ANSWER
        elif self._ring_along:
            decision = IncomingCallDecision.RING
            self._ringing[call.id] = call
            self._ring_timers[call.id] = asyncio.get_running_loop().call_later(
                self._ring_timeout, self._on_ring_timeout, call.id
            )
        else:
            decision = IncomingCallDecision.REJECT
        self._emit(IncomingCall(call, answered=self._auto_answer))
        return decision

    async def _on_call_established(self, dialog: SIPDialog) -> None:
        call = self._new_call(
            dialog.call_id,
            dialog.direction,
            dialog.from_header,
            dialog.to_header,
            dialog.addr,
        )
        self._calls[call.id] = call
        self._emit(CallStarted(call))

    async def _on_call_ended(self, dialog: SIPDialog) -> None:
        call = self._calls.pop(dialog.call_id, None)
        if call is not None:
            self._emit(CallEnded(call))

    async def _on_call_cancelled(self, call_id: str) -> None:
        self._stop_ringing(call_id)
