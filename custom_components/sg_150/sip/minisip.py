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
import logging
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass

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


def parse_sip_message(data: bytes) -> (str, str, dict[str, str]):
    """Parse the SIP package an returns the decoded values."""
    text = data.decode(errors="ignore")
    lines = text.split("\r\n")
    start_line = lines[0]
    method = start_line.split(" ", 1)[0].upper()
    raw_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            raw_headers[k.strip()] = v.strip()
    headers = normalize_headers(raw_headers)
    return start_line, method, headers


def build_response(
    code: str,
    reason: str,
    headers: dict[str, str],
    extra_headers: list[str] | None = None,
    body: str = "",
) -> str:
    """Create a response message."""
    resp_lines = [
        f"SIP/2.0 {code} {reason}",
        f"Via: {headers.get('Via', '')}",
        f"From: {headers.get('From', '')}",
        f"To: {headers.get('To', '')}",
        f"Call-ID: {headers.get('Call-ID', '')}",
        f"CSeq: {headers.get('CSeq', '')}",
        f"Content-Length: {len(body)}",
        "Server: MiniSIP",
    ]
    if extra_headers:
        resp_lines.extend(extra_headers)
    resp_lines.append("")
    resp_lines.append(body)
    return "\r\n".join(resp_lines).encode()


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

    def __init__(  # noqa: PLR0913
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

    def check_cseq(self, headers: dict[str, str], addr: (str, int)) -> bool:
        """Check the CSeq is valid and store it."""
        call_id = headers.get("Call-ID")
        cseq_header = headers.get("CSeq", "")
        cseq_num, _ = self.parse_cseq(cseq_header)
        if call_id and cseq_num is not None:
            last_num = self.last_cseq.get(call_id, -1)
            if cseq_num <= last_num:
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

    def create_unauthorized_response(self, headers: dict[str, str]) -> str:
        """Create an unauthorized response."""
        nonce = self.generate_nonce()
        opaque = self.challenges[nonce] = generate_opaque()
        log_sip_event("REGISTER_CHALLENGE", nonce=nonce, opaque=opaque)
        return build_response(
            401,
            "Unauthorized",
            headers,
            extra_headers=[
                f'WWW-Authenticate: Digest realm="{self.realm}", nonce="{nonce}", opaque="{opaque}", algorithm=MD5, qop="auth"'  # noqa: E501
            ],
        )

    async def handle_register(self, headers: dict[str, str], addr: (str, int)) -> None:
        """Handle the REGISTER method."""
        log_sip_event("REGISTER_RECEIVED", addr=f"{addr}", headers=headers)

        if not self.check_cseq(headers, addr):
            self.transport.sendto(build_response(400, "Bad Request", headers), addr)
            return

        auth_header = headers.get("Authorization")
        if not auth_header:
            self.transport.sendto(self.create_unauthorized_response(headers), addr)
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
            self.transport.sendto(self.create_unauthorized_response(headers), addr)
            return

        expires = self.parse_expires(headers)
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
                headers,
                extra_headers=[f"Expires: {expires}"],
            ),
            addr,
        )

    async def handle_invite(self, headers: dict[str, str], addr: (str, int)) -> None:
        """Handle the INVITE method."""
        call_id = headers.get("Call-ID")
        call_context = CallContext(
            call_id=call_id,
            called_from=headers.get("From"),
            called_to=headers.get("To"),
            addr=addr,
        )

        log_sip_event(
            "INVITE_RECEIVED",
            addr=f"{addr}",
            headers=headers,
            call_context=call_context,
        )

        accept = True
        for cb in self.on_incoming_call:
            result = await cb(call_context)
            if result is False:
                accept = False

        if accept:
            ringing_resp = build_response(180, "Ringing", headers)
            self.transport.sendto(ringing_resp, addr)
            await self._fire_event("on_call_ringing", call_id, addr)
            log_sip_event("CALL_RINGING_SENT", addr=f"{addr}", call_id=call_id)

            sdp = (
                "v=0\r\n"
                f"o=- 123456789 123456789 IN IP4 {self.call_host}\r\n"
                "s=MiniSIP Call\r\n"
                f"c=IN IP4 {self.call_host}\r\n"
                "t=0 0\r\n"
                "m=audio 5005 RTP/AVP 8\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=fmtp:8 0-15\r\n"
            )
            resp = build_response(
                200,
                "OK",
                headers,
                extra_headers=["Content-Type: application/sdp"],
                body=sdp,
            )
            self.transport.sendto(resp, addr)
            self.active_calls[call_id] = (addr, headers.get("From"), headers.get("To"))
            await self._fire_event("on_call_established", call_id, addr)
            log_sip_event("INCOMING_CALL_ACCEPTED", addr=f"{addr}", call_id=call_id)
        else:
            resp = build_response(486, "Busy Here", headers)
            self.transport.sendto(resp, addr)
            log_sip_event("INCOMING_CALL_REJECTED", addr=f"{addr}", call_id=call_id)
            await self._fire_event("on_call_busy", call_id, addr)

    async def handle_bye(self, headers: dict[str, str], addr: (str, int)) -> None:
        """Handle the BYE method."""
        call_id = headers.get("Call-ID")
        log_sip_event("BYE_RECEIVED", addr=f"{addr}", headers=headers, call_id=call_id)

        self.transport.sendto(build_response(200, "OK", headers), addr)
        if call_id in self.active_calls:
            self.active_calls.pop(call_id)
            await self._fire_event("on_call_ended", call_id)

    async def handle_options(self, headers: dict[str, str], addr: (str, int)) -> None:
        """Handle the OPTIONS method."""
        log_sip_event("OPTIONS_RECEIVED", addr=f"{addr}", headers=headers)

        if not self.check_cseq(headers, addr):
            return build_response(400, "Bad Request", headers)

        self.transport.sendto(
            build_response(
                200,
                "OK",
                headers,
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
                    self.active_calls[call_id] = (
                        target_addr,
                        orig_from,
                        headers_resp.get("To"),
                        headers_resp.get("Contact"),
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
        start_line, method, headers = parse_sip_message(data)

        # Delegate response to pending_invites
        if start_line.startswith("SIP/2.0"):
            headers[":start_line"] = start_line
            call_id = headers.get("Call-ID")
            if call_id in self.pending_invites:
                fut = self.pending_invites.pop(call_id)
                if not fut.done():
                    fut.set_result(headers)
            else:
                log_sip_event("GOT SIP/2.0 without pending_invites", headers=headers)
            return

        if method == "REGISTER":
            await self.handle_register(headers, addr)
        elif method == "INVITE":
            await self.handle_invite(headers, addr)
        elif method == "BYE":
            await self.handle_bye(headers, addr)
        elif method == "OPTIONS":
            await self.handle_options(headers, addr)
        elif method == "ACK":
            pass
        else:
            log_sip_event("SIP_METHOD_NOT_IMPLEMENTED", addr=f"{addr}", method=method)
            resp = build_response(501, "Not Implemented", headers)
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
