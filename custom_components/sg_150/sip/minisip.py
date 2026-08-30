"""
MiniSIP: Simple SIP Server.

Very minimal SIP Server that is "good enough" to connect to the Siedle Gateway to
initiate calls.

Currently this is not supporting audio transmission.
"""

import asyncio
import base64
import contextlib
import hashlib
import io
import logging
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np
import soundfile as sf

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
        pcm = _resample_pcm(samples, int(sample_rate))
        return _pcm_to_pcma(pcm)

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


@dataclass
class CallContext:
    """Representation of a call context."""

    call_id: str
    called_from: str
    called_to: str
    addr: tuple[str, int]


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
    ) -> None:
        """Create a new instance of MiniSIPServer."""
        self.host = host
        self.call_host = call_host or host
        self.port: int = port
        self.realm = realm
        self.nonces = set()
        self.expires = expires
        self.users = users  # username -> password
        self.registrations = {}  # username -> {"addr": (ip, port), "expires_at": float}
        self.challenges = {}
        self.pending_invites = {}
        self.active_calls = {}
        self.rtp_sessions = {}
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
                    if info["expires_at"] <= now
                ]

                for user in expired:
                    info = self.registrations.pop(user, None)
                    log_sip_event(
                        "REGISTER_EXPIRED",
                        username=user,
                        addr=f"{info['addr']}" if info else None,
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
        listeners = getattr(self, event_name, [])
        for cb in listeners:
            asyncio.create_task(cb(*args, **kwargs))  # noqa: RUF006 fire and forget

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
    def parse_sdp_media(sdp: str | None) -> dict[str, any] | None:  # noqa: PLR0912
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
        }
        codec_by_pt: dict[int, str] = {}
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
                    payload_types = [
                        int(part)
                        for part in parts[3:]
                        if part.isdigit() and part != "0"
                    ]
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
            if (
                payload_type in codec_by_pt
                and codec_by_pt[payload_type].upper() == "PCMA"
            ):
                media["payload_type"] = payload_type
                media["codec"] = codec_by_pt[payload_type].upper()
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

        self.registrations[username] = {
            "addr": addr,
            "expires_at": time.time() + expires,
        }
        log_sip_event(
            "REGISTER_SUCCESS",
            username=username,
            addr=f"{addr}",
            expires=expires,
        )
        await self._fire_event("on_register", username, addr)

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
        call_context = CallContext(
            call_id=call_id,
            called_from=message.get("From"),
            called_to=message.get("To"),
            addr=addr,
        )

        accept = True
        for cb in self.on_incoming_call:
            result = await cb(call_context)
            if result is False:
                accept = False

        if accept:
            # Update headers to create a valid response with a tag in the To header
            # and a Contact header that matches the To header we assume we always want
            # to accept it.
            message["Contact"] = message.get("To")
            message["To"] = f"{message.get('To')};tag=minisip"

            ringing_resp = build_response(180, "Ringing", message)
            self.transport.sendto(ringing_resp, addr)
            await self._fire_event("on_call_ringing", call_id, addr)
            log_sip_event("CALL_RINGING_SENT", addr=f"{addr}", call_id=call_id)

            sdp = (
                "v=0\r\n"
                f"o=- 123456789 123456789 IN IP4 {self.call_host}\r\n"
                "s=MiniSIP Call\r\n"
                f"c=IN IP4 {self.call_host}\r\n"
                "t=0 0\r\n"
                "m=audio 5004 RTP/AVP 8 101\r\n"
                "a=rtpmap:101 telephone-event/8000\r\n"
                "a=fmtp:101 0-16\r\n"
                "a=ptime:20\r\n"
                "a=maxptime:150\r\n"
                "a=sendrecv"
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

            media = self.parse_sdp_media(message.get(":body"))
            self.active_calls[call_id] = (
                addr,
                message.get("From"),
                message.get("To"),
                message.get("Contact"),
                media or {},
            )

            # This is very optimistic as we did not recive the ACK here
            # a better way would be to only fire this when the ACK was recived.
            await self._fire_event("on_call_established", call_id, addr)
            log_sip_event("INCOMING_CALL_ACCEPTED", addr=f"{addr}", call_id=call_id)
        else:
            resp = build_response(486, "Busy Here", message)
            self.transport.sendto(resp, addr)
            log_sip_event("INCOMING_CALL_REJECTED", addr=f"{addr}", call_id=call_id)
            await self._fire_event("on_call_busy", call_id, addr)

    async def handle_bye(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the BYE method."""
        call_id = message.get("Call-ID")

        self.transport.sendto(build_response(200, "OK", message), addr)
        if call_id in self.active_calls:
            self.active_calls.pop(call_id)
            await self._fire_event("on_call_ended", call_id)

    async def handle_options(self, message: dict[str, str], addr: (str, int)) -> None:
        """Handle the OPTIONS method."""
        if not self.check_cseq(message, addr):
            return build_response(400, "Bad Request", message)

        self.transport.sendto(
            build_response(
                200,
                "OK",
                message,
                extra_headers=[
                    "Allow: REGISTER, ACK, INVITE",
                    "Accept: application/sdp",
                ],
            ),
            addr,
        )

        return None

    async def send_invite(  # noqa: PLR0915
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

        sdp = (
            "v=0\r\n"
            f"o=- 123456789 123456789 IN IP4 {self.call_host}\r\n"
            "s=MiniSIP Call\r\n"
            f"c=IN IP4 {self.call_host}\r\n"
            "t=0 0\r\n"
            "m=audio 5005 RTP/AVP 8\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=fmtp:8 0-15\r\n"
            "a=ptime:20\r\n"
            "a=sendonly"
        )

        call_id = self.new_call_id()
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
                    media = self.parse_sdp_media(headers_resp.get(":body"))
                    self.active_calls[call_id] = (
                        target_addr,
                        orig_from,
                        headers_resp.get("To"),
                        headers_resp.get("Contact"),
                        media or {},
                    )
                    await self._fire_event("on_call_established", call_id, target_addr)
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

    async def send_rtp_audio(self, call_id: str, payload: bytes) -> None:
        """Send a raw PCMA RTP payload to the negotiated media socket."""
        if call_id not in self.active_calls:
            _msg = f"There is currently no active call with call id: {call_id}"
            raise ValueError(_msg)

        call_state = self.active_calls[call_id]
        media = call_state[4] if len(call_state) > 4 else None  # noqa: PLR2004
        if not media:
            _msg = f"No negotiated RTP media for call id: {call_id}"
            raise ValueError(_msg)

        if not payload:
            return

        remote_ip = media.get("ip")
        remote_port = media.get("port")
        payload_type = media.get("payload_type", 8)
        if not remote_ip or remote_port is None:
            _msg = f"No RTP media endpoint available for call id: {call_id}"
            raise ValueError(_msg)

        session = self.rtp_sessions.setdefault(
            call_id,
            {
                "seq": 0,
                "timestamp": 0,
            },
        )
        seq = session["seq"]
        timestamp = session["timestamp"]
        ssrc = 0x12345678

        packet = bytearray(12 + len(payload))
        packet[0] = 0x80
        packet[1] = payload_type & 0x7F
        packet[2] = (seq >> 8) & 0xFF
        packet[3] = seq & 0xFF
        packet[4:8] = timestamp.to_bytes(4, byteorder="big", signed=False)
        packet[8:12] = ssrc.to_bytes(4, byteorder="big", signed=False)
        packet[12:] = payload

        self.transport.sendto(bytes(packet), (remote_ip, remote_port))
        session["seq"] = (seq + 1) & 0xFFFF
        session["timestamp"] = (timestamp + len(payload)) & 0xFFFFFFFF

    async def play_audio(self, call_id: str, mime_type: str, audio_data: bytes) -> None:
        """Send media audio to the negotiated RTP endpoint."""
        pcma = convert_audio_to_pcma(audio_data, mime_type)
        if not pcma:
            return

        chunk_size = 160
        for offset in range(0, len(pcma), chunk_size):
            await asyncio.sleep(0.02)
            await self.send_rtp_audio(call_id, pcma[offset : offset + chunk_size])

    async def send_sip_info_dtmf(
        self, call_id: str, signal: str, duration: str
    ) -> None:
        """Send SIP INFO DTMF."""
        if call_id not in self.active_calls:
            _msg = f"There is currently no active call with call id: {call_id}"
            raise ValueError(_msg)

        addr, from_header, to_header = self.active_calls[call_id][:3]

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

        addr, from_header, to_header = self.active_calls[call_id][:3]

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
        await self._fire_event("on_call_ended", call_id)

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
            pass
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
