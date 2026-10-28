"""
MiniSIP: Simple SIP Server.

Very minimal SIP Server that is "good enough" to connect to the Siedle Gateway to
initiate calls. Each call's audio runs through an RtpSession (see rtp.py).
"""

import asyncio
import base64
import contextlib
import hashlib
import io
import logging
import os
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import numpy as np
import soundfile as sf

from .rtp import (
    CODEC_NAMES,
    PCMA,
    PCMU,
    RtpEndpointFactory,
    RtpPortPool,
    RtpSession,
    open_udp_endpoint,
)

logger = logging.getLogger("sip-server")


def log_sip_event(event: str, **kwargs: any) -> None:
    """Loggin helper for SIP Events."""
    fields = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info("%s %s", event, fields)


def at_address(name: str, host: str) -> str:
    """Format name and host as a @ address."""
    return f"{name}@{host}"


def sip_address(name: str, host: str) -> str:
    """Format name: host as an sip address."""
    return f"<sip:{at_address(name, host)}>"


_SIP_USER = re.compile(r"sips?:([^@;>]+)@")


def sip_user(header: str | None) -> str | None:
    """Return the user part of the SIP URI in a From/To/Contact header."""
    match = _SIP_USER.search(header or "")
    return match.group(1) if match else None


def md5_hex(data: str) -> str:
    """Create MD5 hash from data."""
    return hashlib.md5(data.encode()).hexdigest()  # noqa: S324


def generate_opaque() -> str:
    """Generate a opqaue value."""
    raw = f"{time.time()}:{os.urandom(8).hex()}"
    return base64.b64encode(raw.encode()).decode()


STATUS_SUCCESS_RESPONSE = 200
STATUS_REDIRECT_RESPONSE = 300
STATUS_TRYING = 100
STATUS_RINGING = 180
STATUS_BUSY = 486

# RFC 3261 timers: our 200 OK to an INVITE is resent from T1, doubling up to
# T2, until the ACK arrives or 64 * T1 have passed.
TIMER_T1 = 0.5
TIMER_T2 = 4.0

DEFAULT_RTP_PORTS = range(5004, 5014)

COMPACT_HEADERS = {
    "v": "Via",
    "f": "From",
    "t": "To",
    "i": "Call-ID",
    "l": "Content-Length",
    "c": "Content-Type",
    "m": "Contact",
    "s": "Subject",
    "k": "Supported",
    "o": "Event",
}

STANDARD_HEADERS = {
    "via": "Via",
    "from": "From",
    "to": "To",
    "call-id": "Call-ID",
    "cseq": "CSeq",
    "content-length": "Content-Length",
    "content-type": "Content-Type",
    "contact": "Contact",
    "subject": "Subject",
    "supported": "Supported",
    "event": "Event",
}


TARGET_SAMPLE_RATE = 8000


def _pcm_to_pcma(pcm: np.ndarray) -> bytes:
    """Convert int16 PCM samples to G.711 A-law payload bytes."""
    pcm_array = np.asarray(pcm, dtype=np.int16)
    if pcm_array.size == 0:
        return b""

    buffer = io.BytesIO()
    sf.write(buffer, pcm_array, TARGET_SAMPLE_RATE, format="RAW", subtype="ALAW")
    return buffer.getvalue()


def _resample_pcm(pcm: np.ndarray, sample_rate: int) -> np.ndarray:
    """Resample int16 PCM to 8 kHz using NumPy interpolation."""
    pcm_array = np.asarray(pcm, dtype=np.float64)
    if sample_rate == TARGET_SAMPLE_RATE:
        return pcm_array.astype(np.int16, copy=False)
    if sample_rate <= 0:
        msg = f"Unsupported sample rate: {sample_rate}"
        raise ValueError(msg)

    target_samples = max(1, round(len(pcm_array) * TARGET_SAMPLE_RATE / sample_rate))
    old_x = np.arange(len(pcm_array), dtype=np.float64)
    new_x = np.linspace(0, len(pcm_array) - 1, num=target_samples, dtype=np.float64)
    resampled = np.interp(new_x, old_x, pcm_array)
    return np.clip(resampled, -32768, 32767).astype(np.int16)


def convert_audio_to_pcma(audio_data: bytes, mime_type: str) -> bytes:
    """Convert a media payload to 8 kHz mono G.711 a-law data."""
    return _pcm_to_pcma(convert_audio_to_pcm(audio_data, mime_type))


def convert_audio_to_pcm(audio_data: bytes, mime_type: str) -> np.ndarray:
    """Convert a media payload to 8 kHz mono int16 PCM samples."""
    if not audio_data:
        msg = "No audio data provided."
        raise ValueError(msg)

    if not mime_type:
        msg = "No mime_type provided."
        raise ValueError(msg)

    mime_type = mime_type.lower().strip()

    if mime_type in {
        "audio/ogg",
        "audio/wav",
        "audio/x-wav",
        "audio/mpeg",
        "audio/mp3",
    }:
        wav_buffer = io.BytesIO(audio_data)
        samples, sample_rate = sf.read(wav_buffer, dtype="int16", always_2d=False)
        if np.asarray(samples).ndim > 1:
            samples = samples[:, 0]
        return _resample_pcm(samples, int(sample_rate))

    _msg = f"Unsupported audio media type: {mime_type}"
    raise ValueError(_msg)


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Normalize header keys.

    Ensures that header keys are always in canonical form.
    """
    normalized = {}
    for name, value in headers.items():
        lname = name.lower()
        key = COMPACT_HEADERS.get(lname, STANDARD_HEADERS.get(lname, name))
        if key in normalized:
            normalized[key] += f", {value}"
        else:
            normalized[key] = value
    return normalized


def parse_sip_message(data: bytes) -> (str, dict[str, str]):
    """
    Parse the SIP package and return the decoded values.

    Returns:
        method: The SIP method (e.g., INVITE, REGISTER, BYE).
        message: A dictionary containing the parsed SIP headers and body.

    """
    text = data.decode(errors="ignore")
    lines = text.split("\r\n")
    start_line = lines[0]
    method = start_line.split(" ", 1)[0].upper()
    raw_headers = {}
    body = []
    header_section = True
    for line in lines[1:]:
        if line == "":
            header_section = False
            continue

        if header_section:
            if ":" in line:
                k, v = line.split(":", 1)
                raw_headers[k.strip()] = v.strip()
        else:
            body.append(line)

    message = normalize_headers(raw_headers)
    if body:
        message[":body"] = "\r\n".join(body)

    message[":start_line"] = start_line

    return method, message


def build_response(
    code: str,
    reason: str,
    message: dict[str, str],
    extra_headers: list[str] | None = None,
    body: str | None = None,
) -> str:
    """Create a response message."""
    body_bytes = body.encode() if body is not None else b""
    body_length = len(body_bytes)

    resp_lines = [
        f"SIP/2.0 {code} {reason}",
        f"Via: {message.get('Via', '')}",
        f"From: {message.get('From', '')}",
        f"To: {message.get('To', '')}",
        f"Call-ID: {message.get('Call-ID', '')}",
        f"CSeq: {message.get('CSeq', '')}",
        f"Content-Length: {body_length}",
        "Server: MiniSIP",
    ]

    if "Contact" in message:
        resp_lines.append(f"Contact: {message.get('Contact')}")

    if extra_headers:
        resp_lines.extend(extra_headers)

    resp_lines.append("")  # End of headers

    return ("\r\n".join(resp_lines)).encode() + (
        b"\r\n" + body_bytes if body_length else b""
    )


def build_request(
    method: str, address: (str, int), headers: dict[str, str], body: str | None = None
) -> str:
    """Create a request message."""
    request_lines = [f"{method} sip:{address} SIP/2.0"]
    for k, v in headers.items():
        request_lines.append(f"{k}: {v}")

    request_lines.append(f"Content-Length: {len(body or '')}")
    request_lines.append("")
    if body:
        request_lines.append(body)

    return "\r\n".join(request_lines).encode()


def new_branch_id() -> str:
    """Create a new random branch id."""
    return f"z{random.randint(10000, 99999)}"  # noqa: S311 not crypto relevant


def build_sdp(
    host: str,
    port: int,
    payload_types: list[int],
    telephone_event: int | None = None,
) -> str:
    """Create an SDP body offering or answering sendrecv audio on host:port."""
    formats = [*payload_types] + ([telephone_event] if telephone_event else [])
    lines = [
        "v=0",
        f"o=- 123456789 123456789 IN IP4 {host}",
        "s=MiniSIP Call",
        f"c=IN IP4 {host}",
        "t=0 0",
        f"m=audio {port} RTP/AVP {' '.join(str(pt) for pt in formats)}",
        *(f"a=rtpmap:{pt} {CODEC_NAMES[pt]}/8000" for pt in payload_types),
    ]
    if telephone_event:
        lines += [
            f"a=rtpmap:{telephone_event} telephone-event/8000",
            f"a=fmtp:{telephone_event} 0-16",
        ]
    lines += ["a=ptime:20", "a=sendrecv"]
    return "\r\n".join(lines)


class IncomingCallDecision(Enum):
    """What to do with an incoming call."""

    ANSWER = "answer"
    REJECT = "reject"
    RING = "ring"  # send 180 Ringing and answer or reject it later


def _decision(result: object) -> IncomingCallDecision:
    """Read an on_incoming_call result; True and None answer, False rejects."""
    if isinstance(result, IncomingCallDecision):
        return result
    return (
        IncomingCallDecision.REJECT
        if result is False
        else (IncomingCallDecision.ANSWER)
    )


@dataclass
class CallContext:
    """Representation of a call context."""

    call_id: str
    called_from: str
    called_to: str
    addr: tuple[str, int]


@dataclass(frozen=True)
class SIPRegistration:
    """Where a SIP user is registered, and until when."""

    addr: tuple[str, int]
    expires_at: float


@dataclass(frozen=True)
class SIPDialog:
    """State of an established call."""

    call_id: str
    direction: Literal["incoming", "outgoing"]
    addr: tuple[str, int]
    from_header: str
    to_header: str
    contact: str | None
    media: dict[str, any] = field(default_factory=dict)


@dataclass
class _IncomingInvite:
    """An incoming INVITE that has been sent 180 Ringing but not answered yet."""

    message: dict[str, str]
    addr: tuple[str, int]
    remote_contact: str | None
    media: dict[str, any]


# ============================================================
# SIP Server Class
# ============================================================


class MiniSIPServer:
    """Minimal SIP Server implementation."""

    def __init__(  # noqa: PLR0913, PLR0917
        self,
        users: dict[str, str],
        host: str = "0.0.0.0",  # noqa: S104 exactly what the default should be?
        call_host: str | None = None,
        port: int = 5060,
        expires: int = 3600,
        realm: str = "",
        rtp_ports: range = DEFAULT_RTP_PORTS,
        rtp_endpoint: RtpEndpointFactory = open_udp_endpoint,
    ) -> None:
        """
        Create a new instance of MiniSIPServer.

        rtp_ports: the local UDP ports for call audio, one per concurrent call.
        rtp_endpoint: binds an RtpSession to a port; replaced in tests.
        """
        self.host = host
        self.call_host = call_host or host
        self.port: int = port
        self.realm = realm
        self.nonces = set()
        self.expires = expires
        self.users = users  # username -> password
        self.registrations: dict[str, SIPRegistration] = {}
        self.challenges = {}
        self.pending_invites = {}
        # Incoming calls that are ringing, waiting for answer_call or reject_call.
        self.ringing: dict[str, _IncomingInvite] = {}
        # Accepted incoming calls waiting for the caller's ACK, by call id.
        self.pending_acks: dict[str, SIPDialog] = {}
        self._ack_waits: dict[str, asyncio.Task] = {}
        self.active_calls: dict[str, SIPDialog] = {}
        self.rtp_sessions: dict[str, RtpSession] = {}
        self._rtp_ports: dict[str, int] = {}
        self._port_pool = RtpPortPool(rtp_ports)
        self._rtp_endpoint = rtp_endpoint
        self.last_cseq = {}
        self.transport = None

        # Callbacks: lists for multiple listeners
        self.on_register: list[Callable[..., any]] = []
        self.on_incoming_call: list[Callable[..., any]] = []
        self.on_call_trying: list[Callable[..., any]] = []
        self.on_call_failed: list[Callable[..., any]] = []
        self.on_call_established: list[Callable[..., any]] = []
        self.on_call_ended: list[Callable[..., any]] = []
        self.on_call_ringing: list[Callable[..., any]] = []
        self.on_call_busy: list[Callable[..., any]] = []
        self.on_call_cancelled: list[Callable[..., any]] = []

        # Cleanup loop management
        self._cleanup_task: asyncio.Task | None = None
        self._cleanup_stop = asyncio.Event()

    async def _registration_cleanup_loop(self, interval: int = 10) -> None:
        try:
            while not self._cleanup_stop.is_set():
                now = time.time()
                expired = [
                    user
                    for user, info in self.registrations.items()
                    if info.expires_at <= now
                ]

                for user in expired:
                    info = self.registrations.pop(user, None)
                    log_sip_event(
                        "REGISTER_EXPIRED",
                        username=user,
                        addr=f"{info.addr}" if info else None,
                    )
                    await self._fire_event("on_register", user, None)

                await asyncio.sleep(interval)

        except asyncio.CancelledError:
            pass

    def add_listener(
        self, event_name: str, callback: Callable[..., any]
    ) -> Callable[[], any]:
        """Add a Listener to for a specific event."""
        if not event_name.startswith("on_"):
            _msg = "Event names must start on_"
            raise ValueError(_msg)
        if not hasattr(self, event_name):
            _msg = f"No such event '{event_name}'"
            raise ValueError(_msg)
        lst = getattr(self, event_name)
        lst.append(callback)

        def unsubscribe() -> None:
            """Unsubscribe."""
            with contextlib.suppress(ValueError):
                lst.remove(callback)

        return unsubscribe

    async def _fire_event(
        self, event_name: str, *args: list[any], **kwargs: list[any]
    ) -> None:
        for cb in list(getattr(self, event_name, [])):
            try:
                await cb(*args, **kwargs)
            except Exception:
                logger.exception("Error in %s listener", event_name)

    def sip_user_from(self, name: str) -> str:
        """Get a sip from address."""
        return sip_address(name, self.call_host)

    def new_call_id(self) -> str:
        """Get a new call id."""
        return at_address(random.randint(100000, 999999), self.call_host)  # noqa: S311, no crypto here

    def next_cseq_for(self, call_id: str) -> int:
        """Compute next cseq for a specific call_id."""
        last_cseq = self.last_cseq.get(call_id, 0)
        cseq_num = last_cseq + 1
        self.last_cseq[call_id] = cseq_num
        return cseq_num

    def server_address(self) -> str:
        """Get current server address."""
        return f"{self.call_host}:{self.port}"

    def generate_nonce(self) -> str:
        """Generate and store nonce."""
        nonce = generate_opaque()
        self.nonces.add(nonce)
        return nonce

    def parse_expires(self, headers: dict[str, str]) -> int:
        """Get the expires header."""
        exp = headers.get("Expires")
        if exp is None:
            return self.expires  # Server default expire should be 3600 as per RFC
        try:
            return int(exp)
        except ValueError:
            return self.expires

    def parse_authorization(self, header: dict[str, str]) -> dict[str, str]:
        """Parse the "Digest" header for authorization."""
        if not header.startswith("Digest"):
            return None
        items = {}
        parts = header[len("Digest") :].split(",")
        for part in parts:
            if "=" in part:
                k, v = part.strip().split("=", 1)
                items[k] = v.strip('"')
        return items

    def verify_digest(self, digest: dict[str, str]) -> bool:
        """Verify the digest values are valid."""
        username = digest.get("username")
        realm = digest.get("realm")
        nonce = digest.get("nonce")
        uri = digest.get("uri")
        response = digest.get("response")
        qop = digest.get("qop")
        nc = digest.get("nc")
        cnonce = digest.get("cnonce")
        opaque = digest.get("opaque")

        if (
            not all([username, nonce, uri, response])
            or realm != self.realm
            or username not in self.users
            or nonce not in self.nonces
            or self.challenges.get(nonce) != opaque
        ):
            return False

        password = self.users[username]
        ha1 = md5_hex(f"{username}:{realm}:{password}")
        ha2 = md5_hex(f"REGISTER:{uri}")

        if qop == "auth":
            if not all([nc, cnonce]):
                return False
            expected = md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        else:
            expected = md5_hex(f"{ha1}:{nonce}:{ha2}")

        return expected == response

    def parse_cseq(self, cseq_header: str) -> (int, str):
        """Parse the CSeq header to extract method and number."""
        if not cseq_header:
            return None, None
        parts = cseq_header.strip().split()
        expected_parts = 2
        if len(parts) != expected_parts:
            return None, None
        try:
            num = int(parts[0])
            method = parts[1].upper()
        except ValueError:
            return None, None

        return num, method

    @staticmethod
    def parse_sdp_media(sdp: str | None) -> dict[str, any] | None:  # noqa: PLR0912, PLR0915
        """Parse SDP media metadata from a SIP SDP body."""
        if not sdp:
            return None

        media: dict[str, any] = {
            "ip": None,
            "port": None,
            "payload_type": None,
            "codec": None,
            "ptime": None,
            "direction": "sendrecv",
            "telephone_event": None,
        }
        # Static payload types need no rtpmap line.
        codec_by_pt: dict[int, str] = dict(CODEC_NAMES)
        payload_types: list[int] = []

        for line in sdp.splitlines():
            if not line:
                continue

            if line.startswith("c="):
                parts = line.split()
                if len(parts) >= 3:  # noqa: PLR2004
                    media["ip"] = parts[2]
            elif line.startswith("m="):
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "m=audio":  # noqa: PLR2004
                    try:
                        media["port"] = int(parts[1])
                    except ValueError:
                        media["port"] = None
                    payload_types = [int(part) for part in parts[3:] if part.isdigit()]
            elif line.startswith("a=rtpmap:"):
                parts = line.split()
                if len(parts) >= 2:  # noqa: PLR2004
                    pt = parts[0].split(":", 1)[1]
                    try:
                        payload_type = int(pt)
                    except ValueError:
                        continue
                    codec_name = parts[1].split("/", 1)[0]
                    codec_by_pt[payload_type] = codec_name
            elif line.startswith("a=ptime:"):
                try:
                    media["ptime"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    media["ptime"] = None
            elif line.startswith("a=") and line[2:].strip().lower() in {
                "sendrecv",
                "sendonly",
                "recvonly",
                "inactive",
            }:
                media["direction"] = line[2:].strip().lower()

        for payload_type in payload_types:
            if "event" in codec_by_pt.get(payload_type, "").lower():
                media["telephone_event"] = payload_type
                break

        # Prefer PCMA, then PCMU: the codecs RtpSession can send.
        for codec in ("PCMA", "PCMU"):
            for payload_type in payload_types:
                if codec_by_pt.get(payload_type, "").upper() == codec:
                    media["payload_type"] = payload_type
                    media["codec"] = codec
                    break
            if media["payload_type"] is not None:
                break

        if media["payload_type"] is None and payload_types:
            for payload_type in payload_types:
                if (
                    payload_type in codec_by_pt
                    and "event" not in codec_by_pt[payload_type].lower()
                ):
                    media["payload_type"] = payload_type
                    media["codec"] = codec_by_pt[payload_type].upper()
                    break
            if media["payload_type"] is None:
                media["payload_type"] = payload_types[0]
                media["codec"] = codec_by_pt.get(payload_types[0], "UNKNOWN").upper()

        return media

    def check_cseq(self, message: dict[str, str], addr: (str, int)) -> bool:
        """Check the CSeq is valid and store it."""
        call_id = message.get("Call-ID")
        cseq_header = message.get("CSeq", "")
        cseq_num, _ = self.parse_cseq(cseq_header)
        if call_id and cseq_num is not None:
            last_num = self.last_cseq.get(call_id, -1)
            if cseq_num < last_num:
                log_sip_event(
                    "OLD_CSEQ",
                    addr=f"{addr}",
                    call_id=call_id,
                    cseq=cseq_num,
                    last=last_num,
                )
                return False
            self.last_cseq[call_id] = cseq_num
        return True

    def create_unauthorized_response(self, message: dict[str, str]) -> str:
        """Create an unauthorized response."""
        nonce = self.generate_nonce()
        opaque = self.challenges[nonce] = generate_opaque()
        log_sip_event("REGISTER_CHALLENGE", nonce=nonce, opaque=opaque)
        return build_response(
            401,
            "Unauthorized",
            message,
            extra_headers=[
                f'WWW-Authenticate: Digest realm="{self.realm}", nonce="{nonce}", opaque="{opaque}", algorithm=MD5, qop="auth"'  # noqa: E501
            ],
        )

    async def handle_register(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the REGISTER method."""
        if not self.check_cseq(message, addr):
            self.transport.sendto(build_response(400, "Bad Request", message), addr)
            return

        auth_header = message.get("Authorization")
        if not auth_header:
            self.transport.sendto(self.create_unauthorized_response(message), addr)
            return

        auth = self.parse_authorization(auth_header)
        if not auth or not self.verify_digest(auth):
            log_sip_event(
                "REGISTER_FAILED_AUTH",
                addr=f"{addr}",
                username=auth.get("username") if auth else None,
                nonce=auth.get("nonce") if auth else None,
                opaque=auth.get("opaque") if auth else None,
            )
            self.transport.sendto(self.create_unauthorized_response(message), addr)
            return

        expires = self.parse_expires(message)
        username = auth.get("username")

        registration = SIPRegistration(addr=addr, expires_at=time.time() + expires)
        self.registrations[username] = registration
        log_sip_event(
            "REGISTER_SUCCESS",
            username=username,
            addr=f"{addr}",
            expires=expires,
        )
        await self._fire_event("on_register", username, registration)

        self.transport.sendto(
            build_response(
                200,
                "OK",
                message,
                extra_headers=[f"Expires: {expires}"],
            ),
            addr,
        )

    async def handle_invite(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the INVITE method."""
        call_id = message.get("Call-ID")
        if (
            call_id in self.ringing
            or call_id in self.pending_acks
            or call_id in self.active_calls
        ):
            # A retransmission, or a re-INVITE we don't support: keep the call.
            log_sip_event("INVITE_IGNORED", addr=f"{addr}", call_id=call_id)
            return

        call_context = CallContext(
            call_id=call_id,
            called_from=message.get("From"),
            called_to=message.get("To"),
            addr=addr,
        )

        decisions = [_decision(await cb(call_context)) for cb in self.on_incoming_call]
        if IncomingCallDecision.REJECT in decisions:
            resp = build_response(486, "Busy Here", message)
            self.transport.sendto(resp, addr)
            log_sip_event("INCOMING_CALL_REJECTED", addr=f"{addr}", call_id=call_id)
            await self._fire_event("on_call_busy", call_id, addr)
            return

        # Answer with a tag in the To header, and a Contact pointing at our own
        # host and port so the caller's ACK and later requests reach us.
        invite = _IncomingInvite(
            message=message,
            addr=addr,
            remote_contact=message.get("Contact"),
            media=self.parse_sdp_media(message.get(":body")) or {},
        )
        message["Contact"] = sip_address(
            sip_user(message.get("To")) or "", self.server_address()
        )
        message["To"] = f"{message.get('To')};tag=minisip"

        ringing_resp = build_response(180, "Ringing", message)
        self.transport.sendto(ringing_resp, addr)
        await self._fire_event("on_call_ringing", call_id, addr)
        log_sip_event("CALL_RINGING_SENT", addr=f"{addr}", call_id=call_id)

        if IncomingCallDecision.RING in decisions:
            self.ringing[call_id] = invite
            return

        await self._answer_invite(invite)

    async def answer_call(self, call_id: str) -> None:
        """Answer an incoming call that is ringing."""
        invite = self.ringing.pop(call_id, None)
        if invite is None:
            _msg = f"There is currently no ringing call with call id: {call_id}"
            raise ValueError(_msg)
        await self._answer_invite(invite)

    async def reject_call(self, call_id: str) -> None:
        """Reject an incoming call that is ringing as busy."""
        invite = self.ringing.pop(call_id, None)
        if invite is None:
            _msg = f"There is currently no ringing call with call id: {call_id}"
            raise ValueError(_msg)
        self.transport.sendto(
            build_response(486, "Busy Here", invite.message), invite.addr
        )
        log_sip_event("INCOMING_CALL_REJECTED", addr=f"{invite.addr}", call_id=call_id)
        await self._fire_event("on_call_busy", call_id, invite.addr)

    async def _answer_invite(self, invite: _IncomingInvite) -> None:
        """Open the call's RTP session and send 200 OK with our SDP answer."""
        message, addr, media = invite.message, invite.addr, invite.media
        call_id = message.get("Call-ID")

        payload_type = media.get("payload_type", PCMA) if media else PCMA
        if payload_type not in CODEC_NAMES:
            self.transport.sendto(
                build_response(488, "Not Acceptable Here", message), addr
            )
            log_sip_event("INCOMING_CALL_NO_CODEC", addr=f"{addr}", call_id=call_id)
            await self._fire_event("on_call_failed", call_id, addr, 488)
            return

        remote = (
            (media["ip"], media["port"])
            if media.get("ip") and media.get("port")
            else None
        )
        port = await self._open_rtp(
            call_id, RtpSession(payload_type=payload_type, remote=remote)
        )
        if port is None:
            self.transport.sendto(
                build_response(503, "Service Unavailable", message), addr
            )
            await self._fire_event("on_call_failed", call_id, addr, 503)
            return

        sdp = build_sdp(
            self.call_host, port, [payload_type], media.get("telephone_event")
        )
        resp = build_response(
            200,
            "OK",
            message,
            extra_headers=[
                "Content-Type: application/sdp",
            ],
            body=sdp,
        )
        self.transport.sendto(resp, addr)

        # The call is established once the caller ACKs our 200 OK.
        self.pending_acks[call_id] = SIPDialog(
            call_id=call_id,
            direction="incoming",
            addr=addr,
            from_header=message.get("From"),
            to_header=message.get("To"),
            contact=invite.remote_contact,
            media=media,
        )
        self._ack_waits[call_id] = asyncio.create_task(
            self._resend_until_ack(call_id, resp, addr),
            name=f"sip-ack-wait-{call_id}",
        )
        log_sip_event("INCOMING_CALL_ACCEPTED", addr=f"{addr}", call_id=call_id)

    async def _resend_until_ack(
        self, call_id: str, response: bytes, addr: tuple[str, int]
    ) -> None:
        """Resend our 200 OK until the ACK arrives, as UDP may lose either."""
        interval, waited = TIMER_T1, 0.0
        while waited < 64 * TIMER_T1:
            await asyncio.sleep(interval)
            waited += interval
            if call_id not in self.pending_acks:
                return
            self.transport.sendto(response, addr)
            log_sip_event("OK_RESENT", addr=f"{addr}", call_id=call_id)
            interval = min(interval * 2, TIMER_T2)

        self._ack_waits.pop(call_id, None)
        if self.pending_acks.pop(call_id, None) is not None:
            log_sip_event("ACK_TIMEOUT", addr=f"{addr}", call_id=call_id)
            self._close_rtp(call_id)

    def _stop_ack_wait(self, call_id: str) -> None:
        if (task := self._ack_waits.pop(call_id, None)) is not None:
            task.cancel()

    async def _open_rtp(self, call_id: str, session: RtpSession) -> int | None:
        """Bind `session` to a free RTP port for the call and return the port."""
        port = self._port_pool.acquire()
        if port is None:
            log_sip_event("RTP_NO_FREE_PORT", call_id=call_id)
            return None
        try:
            await self._rtp_endpoint(session, self.host, port)
        except OSError as err:
            self._port_pool.release(port)
            log_sip_event("RTP_BIND_FAILED", call_id=call_id, port=port, error=err)
            return None
        self.rtp_sessions[call_id] = session
        self._rtp_ports[call_id] = port
        return port

    def _close_rtp(self, call_id: str) -> None:
        """Close the call's RTP session and free its port."""
        if (session := self.rtp_sessions.pop(call_id, None)) is not None:
            session.close()
        if (port := self._rtp_ports.pop(call_id, None)) is not None:
            self._port_pool.release(port)

    async def handle_ack(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the ACK method, which establishes an accepted incoming call."""
        call_id = message.get("Call-ID")
        dialog = self.pending_acks.pop(call_id, None)
        if dialog is None:
            return

        self._stop_ack_wait(call_id)
        self.active_calls[call_id] = dialog
        if (session := self.rtp_sessions.get(call_id)) is not None:
            session.start()
        log_sip_event("INCOMING_CALL_ESTABLISHED", addr=f"{addr}", call_id=call_id)
        await self._fire_event("on_call_established", dialog)

    async def handle_bye(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the BYE method."""
        call_id = message.get("Call-ID")

        self.transport.sendto(build_response(200, "OK", message), addr)
        if self.pending_acks.pop(call_id, None) is not None:
            self._stop_ack_wait(call_id)
            self._close_rtp(call_id)
            log_sip_event("CALL_ENDED_BEFORE_ACK", addr=f"{addr}", call_id=call_id)
        elif call_id in self.active_calls:
            dialog = self.active_calls.pop(call_id)
            self._close_rtp(call_id)
            await self._fire_event("on_call_ended", dialog)

    async def handle_cancel(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle CANCEL, sent when the caller gives up or another phone answered."""
        call_id = message.get("Call-ID")
        invite = self.ringing.pop(call_id, None)
        if invite is None:
            # Already answered (CANCEL has no effect then) or unknown.
            known = call_id in self.pending_acks or call_id in self.active_calls
            self.transport.sendto(
                build_response(200, "OK", message)
                if known
                else build_response(481, "Call/Transaction Does Not Exist", message),
                addr,
            )
            return

        self.transport.sendto(build_response(200, "OK", message), addr)
        self.transport.sendto(
            build_response(487, "Request Terminated", invite.message), invite.addr
        )
        log_sip_event("INCOMING_CALL_CANCELLED", addr=f"{addr}", call_id=call_id)
        await self._fire_event("on_call_cancelled", call_id)

    async def handle_options(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the OPTIONS method."""
        if not self.check_cseq(message, addr):
            self.transport.sendto(build_response(400, "Bad Request", message), addr)
            return

        self.transport.sendto(
            build_response(
                200,
                "OK",
                message,
                extra_headers=[
                    "Allow: REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS",
                    "Accept: application/sdp",
                ],
            ),
            addr,
        )

    async def send_invite(
        self,
        target_addr: str,
        from_user: str,
        to_user: str,
        timeout: int = 10,  # noqa: ASYNC109
    ) -> (str, dict[str, str]):
        """Send a INVITE."""
        if not from_user or not to_user:
            _msg = "from_user and to_user are required"
            raise ValueError(_msg)

        call_id = self.new_call_id()
        # The codec and remote address are filled in from the SDP answer.
        port = await self._open_rtp(call_id, RtpSession())
        if port is None:
            return None, None
        try:
            return await self._send_invite(
                call_id, port, target_addr, from_user, to_user, timeout
            )
        finally:
            if call_id not in self.active_calls:
                self._close_rtp(call_id)

    async def _send_invite(  # noqa: PLR0913, PLR0915, PLR0917
        self,
        call_id: str,
        rtp_port: int,
        target_addr: str,
        from_user: str,
        to_user: str,
        timeout: int,  # noqa: ASYNC109
    ) -> (str, dict[str, str]):
        sdp = build_sdp(self.call_host, rtp_port, [PCMA, PCMU])
        cseq_num = self.next_cseq_for(call_id)
        orig_from = self.sip_user_from(from_user)

        headers = {
            "Via": f"SIP/2.0/UDP {self.server_address()};branch={new_branch_id()}",
            "From": orig_from,
            "To": sip_address(to_user, target_addr[0]),
            "Call-ID": call_id,
            "CSeq": f"{cseq_num} INVITE",
            "Contact": orig_from,
            "Content-Type": "application/sdp",
        }

        data = build_request(
            "INVITE", at_address(to_user, target_addr[0]), headers=headers, body=sdp
        )
        self.transport.sendto(data, target_addr)

        log_sip_event("INVITE_SENT", addr=f"{target_addr}", call_id=call_id)
        fut = asyncio.get_running_loop().create_future()
        self.pending_invites[call_id] = fut

        call_state = {"status": "INVITE_SENT", "final": False}

        try:
            while not call_state["final"]:
                headers_resp = await asyncio.wait_for(fut, timeout)
                status_line = headers_resp.get(":start_line", "")
                code = int(status_line.split()[1]) if status_line else 0

                if code == STATUS_TRYING:
                    log_sip_event("TRYING", addr=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "TRYING"
                    await self._fire_event("on_call_trying", call_id, target_addr)
                    fut = asyncio.get_running_loop().create_future()
                    self.pending_invites[call_id] = fut

                elif code == STATUS_RINGING:
                    log_sip_event("RINGING", addr=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "RINGING"
                    await self._fire_event("on_call_ringing", call_id, target_addr)
                    fut = asyncio.get_running_loop().create_future()
                    self.pending_invites[call_id] = fut

                elif code == STATUS_BUSY:
                    log_sip_event("BUSY", addr=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "BUSY"
                    call_state["final"] = True
                    self.pending_invites.pop(call_id, None)
                    await self._fire_event("on_call_busy", call_id, target_addr)
                    return None, None
                # Any success response
                elif STATUS_SUCCESS_RESPONSE <= code < STATUS_REDIRECT_RESPONSE:
                    log_sip_event("CONNECTED", addr=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "CONNECTED"
                    call_state["final"] = True
                    await self.send_ack(headers_resp, target_addr)
                    media = self.parse_sdp_media(headers_resp.get(":body")) or {}
                    session = self.rtp_sessions[call_id]
                    if media.get("payload_type") in CODEC_NAMES:
                        session.payload_type = media["payload_type"]
                    if media.get("ip") and media.get("port"):
                        session.remote = (media["ip"], media["port"])
                    dialog = SIPDialog(
                        call_id=call_id,
                        direction="outgoing",
                        addr=target_addr,
                        from_header=orig_from,
                        to_header=headers_resp.get("To"),
                        contact=headers_resp.get("Contact"),
                        media=media,
                    )
                    self.active_calls[call_id] = dialog
                    session.start()
                    await self._fire_event("on_call_established", dialog)
                    return call_id, headers_resp

                else:
                    log_sip_event(
                        "CALL_FAILED",
                        addr=f"{target_addr}",
                        call_id=call_id,
                        code=code,
                    )
                    call_state["status"] = "FAILED"
                    call_state["final"] = True
                    self.pending_invites.pop(call_id, None)
                    await self._fire_event("on_call_failed", call_id, target_addr, code)
                    return None, None

        except TimeoutError:
            log_sip_event("INVITE_TIMEOUT", addr=f"{target_addr}", call_id=call_id)
            self.pending_invites.pop(call_id, None)
            return None, None

    async def send_ack(self, resp_headers: dict[str, str], target_addr: str) -> None:
        """Send a ACK."""
        call_id = resp_headers.get("Call-ID")
        cseq_num, _ = self.parse_cseq(resp_headers.get("CSeq"))
        to_address = resp_headers.get("To").split("<")[1].split(">")[0]

        headers = {
            "Via": f"SIP/2.0/UDP {self.server_address()};branch={new_branch_id()}",
            "From": resp_headers.get("From"),
            "To": resp_headers.get("To"),
            "Call-ID": call_id,
            "CSeq": f"{cseq_num} ACK",
            "Contact": resp_headers.get("Contact"),
        }

        data = build_request("ACK", to_address, headers=headers)
        self.transport.sendto(data, target_addr)
        log_sip_event("ACK_SENT", addr=f"{target_addr}", call_id=call_id)

    def rtp_session(self, call_id: str) -> RtpSession:
        """Return the RTP session of an established call."""
        if call_id not in self.active_calls or call_id not in self.rtp_sessions:
            _msg = f"There is currently no active call with call id: {call_id}"
            raise ValueError(_msg)
        return self.rtp_sessions[call_id]

    async def play_audio(self, call_id: str, mime_type: str, audio_data: bytes) -> None:
        """Send media audio into the call and wait until it has been sent."""
        session = self.rtp_session(call_id)
        session.write_pcm(convert_audio_to_pcm(audio_data, mime_type))
        await session.drain()

    async def send_sip_info_dtmf(
        self, call_id: str, signal: str, duration: str
    ) -> None:
        """Send SIP INFO DTMF."""
        if call_id not in self.active_calls:
            _msg = f"There is currently no active call with call id: {call_id}"
            raise ValueError(_msg)

        dialog = self.active_calls[call_id]
        addr, from_header, to_header = dialog.addr, dialog.from_header, dialog.to_header

        cseq_num = self.next_cseq_for(call_id)
        headers = {
            "Via": f"SIP/2.0/UDP {self.server_address()};branch={new_branch_id()}",
            "From": from_header,
            "To": to_header,
            "Call-ID": call_id,
            "CSeq": f"{cseq_num} INFO",
            "Content-Type": "application/dtmf-relay",
            "Contact": from_header,
        }

        body = f"Signal={signal}\r\nDuration={duration}"
        data = build_request("INFO", to_header, headers=headers, body=body)
        self.transport.sendto(data, addr)
        log_sip_event("INFO_SENT", addr=f"{addr}", call_id=call_id, request=data)

    async def send_bye(self, call_id: str) -> None:
        """Send BYE response."""
        if call_id not in self.active_calls:
            _msg = f"There is currently no active call with call id: {call_id}"
            raise ValueError(_msg)

        dialog = self.active_calls[call_id]
        addr, from_header, to_header = dialog.addr, dialog.from_header, dialog.to_header

        cseq_num = self.next_cseq_for(call_id)
        headers = {
            "Via": f"SIP/2.0/UDP {self.server_address()};branch={new_branch_id()}",
            "From": from_header,
            "To": to_header,
            "Call-ID": call_id,
            "CSeq": f"{cseq_num} BYE",
            "Contact": from_header,
        }

        data = build_request("BYE", to_header, headers=headers)
        self.transport.sendto(data, addr)
        log_sip_event("BYE_SENT", addr=f"{addr}", call_id=call_id)
        self.active_calls.pop(call_id)
        self._close_rtp(call_id)
        await self._fire_event("on_call_ended", dialog)

    async def handle_datagram(self, data: bytes, addr: (str, int)) -> None:
        """Handle a raw UDP datagram."""
        method, message = parse_sip_message(data)
        log_sip_event(method, addr=f"{addr}", message=message)

        # Delegate response to pending_invites
        if message[":start_line"].startswith("SIP/2.0"):
            call_id = message.get("Call-ID")
            if call_id in self.pending_invites:
                fut = self.pending_invites.pop(call_id)
                if not fut.done():
                    fut.set_result(message)
            return

        if method == "REGISTER":
            await self.handle_register(message, addr)
        elif method == "INVITE":
            await self.handle_invite(message, addr)
        elif method == "BYE":
            await self.handle_bye(message, addr)
        elif method == "OPTIONS":
            await self.handle_options(message, addr)
        elif method == "ACK":
            await self.handle_ack(message, addr)
        elif method == "CANCEL":
            await self.handle_cancel(message, addr)
        else:
            log_sip_event("SIP_METHOD_NOT_IMPLEMENTED", addr=f"{addr}", method=method)
            resp = build_response(501, "Not Implemented", message)
            self.transport.sendto(resp, addr)

    async def start(self) -> None:
        """Start the MiniSIP Server."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SIPProtocol(self),
            local_addr=(self.host, self.port),
        )
        self.transport = transport

        # Start cleanup loop
        self._cleanup_stop.clear()
        self._cleanup_task = asyncio.create_task(
            self._registration_cleanup_loop(),
            name="sip-registration-cleanup",
        )

        logger.info("SIP server listening on %s:%d (UDP)", self.host, self.port)

    async def stop(self) -> None:
        """Shutdown the MiniSIP Server."""
        if self._cleanup_task:
            self._cleanup_stop.set()
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            self._cleanup_task = None

        for task in self._ack_waits.values():
            task.cancel()
        self._ack_waits.clear()
        for call_id in list(self.rtp_sessions):
            self._close_rtp(call_id)

        if self.transport:
            self.transport.close()
            self.transport = None


class SIPProtocol(asyncio.DatagramProtocol):
    """Delegates SIP to the MiniSIP Server class."""

    def __init__(self, server: MiniSIPServer) -> None:
        """Create a new MiniSIP Protocol."""
        self.server = server

    def datagram_received(self, data: bytes, addr: (str, int)) -> None:
        """Delegate to server."""
        asyncio.create_task(self.server.handle_datagram(data, addr))  # noqa: RUF006, fire and forget

    def error_received(self, exc: Exception) -> None:
        """Log transport issues."""
        logger.error("Transport error: %s", exc)
