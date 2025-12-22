import asyncio
import logging
import hashlib
import time
import os
import base64
import random
import re

from dataclasses import dataclass

logger = logging.getLogger("sip-server")


def log_sip_event(event, **kwargs):
    fields = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info(f"{event} {fields}")


def at_address(name, host):
    return f"{name}@{host}"


def sip_address(name, host):
    return f"<sip:{at_address(name, host)}>"


# ============================================================
# Hashing
# ============================================================
def md5_hex(data):
    return hashlib.md5(data.encode()).hexdigest()


def generate_opaque():
    raw = f"{time.time()}:{os.urandom(8).hex()}"
    return base64.b64encode(raw.encode()).decode()


# ============================================================
# SIP Header Normalization
# ============================================================
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


def normalize_headers(headers):
    normalized = {}
    for name, value in headers.items():
        lname = name.lower()
        key = COMPACT_HEADERS.get(lname, STANDARD_HEADERS.get(lname, name))
        if key in normalized:
            normalized[key] += f", {value}"
        else:
            normalized[key] = value
    return normalized


def parse_sip_message(data):
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


def build_response(code, reason, headers, extra_headers=None, body=""):
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


def build_request(method, address, headers, body=None):
    request_lines = [f"{method} sip:{address} SIP/2.0"]
    for k, v in headers.items():
        request_lines.append(f"{k}: {v}")

    request_lines.append(f"Content-Length: {len(body or '')}")
    request_lines.append("")
    if body:
        request_lines.append(body)

    return "\r\n".join(request_lines).encode()


def new_branch_id():
    return f"z{random.randint(10000, 99999)}"


@dataclass
class CallContext:
    """
    Representation of a call context
    """
    call_id: str
    calledFrom: str
    calledTo: str
    addr: tuple[str, int]

# ============================================================
# SIP Server Class
# ============================================================


class MiniSIPServer:
    def __init__(self, users, host="0.0.0.0", call_host: str = None, port=5060, expires=3600, realm=""):
        self.host = host
        self.call_host = call_host or host
        self.port = port
        self.realm = realm
        self.nonces = set()
        self.expires = expires
        self.users = users
        self.registrations = {}
        self.challenges = {}
        self.pending_invites = {}
        self.active_calls = {}
        self.last_cseq = {}
        self.transport = None

        # Callbacks: lists for multiple listeners
        self.on_register = []
        self.on_incoming_call = []
        self.on_call_trying = []
        self.on_call_failed = []
        self.on_call_established = []
        self.on_call_ended = []
        self.on_call_ringing = []
        self.on_call_busy = []

    # ============================================================
    # Listener Management
    # ============================================================

    def add_listener(self, event_name: str, callback):
        if not event_name.startswith("on_"):
            raise ValueError(f"Event names must start on_")
        if not hasattr(self, event_name):
            raise ValueError(f"No such event '{event_name}'")
        lst = getattr(self, event_name)
        lst.append(callback)

        def unsubscribe():
            try:
                lst.remove(callback)
            except ValueError:
                pass  # already removed

        return unsubscribe

    async def _fire_event(self, event_name, *args, **kwargs):
        listeners = getattr(self, event_name, [])
        for cb in listeners:
            asyncio.create_task(cb(*args, **kwargs))

    # ============================================================
    # SIP Utility Methods
    # ============================================================

    def sip_user_from(self, name: str):
        return sip_address(name, self.call_host)

    def new_call_id(self):
        return at_address(random.randint(100000, 999999), self.call_host)

    def next_cseq_for(self, call_id):
        last_cseq = self.last_cseq.get(call_id, 0)
        cseq_num = last_cseq + 1
        self.last_cseq[call_id] = cseq_num
        return cseq_num

    def server_address(self):
        return f"{self.call_host}:{self.port}"

    def generate_nonce(self):
        nonce = generate_opaque()
        self.nonces.add(nonce)
        return nonce

    def parse_authorization(self, header):
        if not header.startswith("Digest"):
            return None
        items = {}
        parts = header[len("Digest"):].split(",")
        for part in parts:
            if "=" in part:
                k, v = part.strip().split("=", 1)
                items[k] = v.strip('"')
        return items

    def verify_digest(self, auth):
        username = auth.get("username")
        realm = auth.get("realm")
        nonce = auth.get("nonce")
        uri = auth.get("uri")
        response = auth.get("response")
        qop = auth.get("qop")
        nc = auth.get("nc")
        cnonce = auth.get("cnonce")
        opaque = auth.get("opaque")

        if not all([username, nonce, uri, response]):
            return False
        if realm != self.realm:
            return False
        if username not in self.users:
            return False
        if nonce not in self.nonces:
            return False
        if self.challenges.get(nonce) != opaque:
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

    def parse_cseq(self, cseq_header):
        if not cseq_header:
            return None, None
        parts = cseq_header.strip().split()
        if len(parts) != 2:
            return None, None
        try:
            num = int(parts[0])
            method = parts[1].upper()
            return num, method
        except ValueError:
            return None, None

    def check_cseq(self, headers, addr):
        call_id = headers.get("Call-ID")
        cseq_header = headers.get("CSeq", "")
        cseq_num, _ = self.parse_cseq(cseq_header)
        if call_id and cseq_num is not None:
            last_num = self.last_cseq.get(call_id, -1)
            if cseq_num <= last_num:
                log_sip_event(
                    "OLD_CSEQ",
                    client=f"{addr}",
                    call_id=call_id,
                    cseq=cseq_num,
                    last=last_num,
                )
                return False
            self.last_cseq[call_id] = cseq_num
        return True

    def create_unauthorized_response(self, headers):
        nonce = self.generate_nonce()
        opaque = self.challenges[nonce] = generate_opaque()
        log_sip_event("REGISTER_CHALLENGE", nonce=nonce, opaque=opaque)
        return build_response(
            401,
            "Unauthorized",
            headers,
            extra_headers=[
                f'WWW-Authenticate: Digest realm="{self.realm}", nonce="{nonce}", opaque="{opaque}", algorithm=MD5, qop="auth"'
            ],
        )

    # ============================================================
    # Event Handlers
    # ============================================================

    async def handle_register(self, headers, addr):
        if not self.check_cseq(headers, addr):
            self.transport.sendto(
                build_response(400, "Bad Request", headers),
                addr
            )

        auth_header = headers.get("Authorization")
        if not auth_header:
            self.transport.sendto(
                self.create_unauthorized_response(headers),
                addr
            )
            return

        auth = self.parse_authorization(auth_header)
        if not auth or not self.verify_digest(auth):
            log_sip_event(
                "REGISTER_FAILED_AUTH",
                client=f"{addr}",
                username=auth.get("username") if auth else None,
                nonce=auth.get("nonce") if auth else None,
                opaque=auth.get("opaque") if auth else None,
            )
            self.transport.sendto(
                self.create_unauthorized_response(headers),
                addr
            )
            return

        username = auth.get("username")
        self.registrations[username] = addr
        log_sip_event("REGISTER_SUCCESS", client=f"{addr}", username=username)

        await self._fire_event("on_register", username, addr)

        self.transport.sendto(
            build_response(200, "OK", headers, extra_headers=[
                           f"Expires: {self.expires}"]),
            addr
        )

    async def handle_invite(self, headers, addr):
        log_sip_event("INVITE_RECEIVED", client=f"{addr}")

        call_id = headers.get("Call-ID")
        call_context = CallContext(
            call_id=call_id,
            calledFrom=headers.get("From"),
            calledTo=headers.get("To"),
            addr=addr
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
            log_sip_event("CALL_RINGING_SENT",
                          client=f"{addr}", call_id=call_id)

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
                200, "OK", headers, extra_headers=["Content-Type: application/sdp"], body=sdp
            )
            self.transport.sendto(resp, addr)
            self.active_calls[call_id] = (
                addr, headers.get('From'), headers.get('To'))
            await self._fire_event("on_call_established", call_id, addr)
            log_sip_event("INCOMING_CALL_ACCEPTED",
                          client=f"{addr}", call_id=call_id)
        else:
            resp = build_response(486, "Busy Here", headers)
            self.transport.sendto(resp, addr)
            log_sip_event("INCOMING_CALL_REJECTED",
                          client=f"{addr}", call_id=call_id)
            await self._fire_event("on_call_busy", call_id, addr)

    async def handle_bye(self, headers, addr):
        call_id = headers.get("Call-ID")
        log_sip_event("BYE_RECEIVED", client=f"{addr}", call_id=call_id)

        self.transport.sendto(build_response(200, "OK", headers), addr)
        if call_id in self.active_calls:
            self.active_calls.pop(call_id)
            await self._fire_event("on_call_ended", call_id)

    async def handle_options(self, headers, addr):
        log_sip_event("OPTIONS_RECEIVED", client=f"{addr}")

        if not self.check_cseq(headers, addr):
            return build_response(400, "Bad Request", headers)

        self.transport.sendto(
            build_response(
                200, "OK", headers,
                extra_headers=["Allow: REGISTER, ACK, INVITE",
                               "Accept: application/sdp"]
            ),
            addr
        )

    # ============================================================
    # SIP Actions: INVITE, ACK, BYE, INFO
    # ============================================================

    async def send_invite(self, target_addr, from_user, to_user, timeout=10):
        if not from_user or not to_user:
            raise ValueError("from_user and to_user are required")

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

        data = build_request("INVITE", at_address(
            to_user, target_addr[0]), headers=headers, body=sdp)
        self.transport.sendto(data, target_addr)

        log_sip_event("INVITE_SENT", client=f"{target_addr}", call_id=call_id)
        fut = asyncio.get_running_loop().create_future()
        self.pending_invites[call_id] = fut

        call_state = {"status": "INVITE_SENT", "final": False}

        try:
            while not call_state["final"]:
                headers_resp = await asyncio.wait_for(fut, timeout)
                status_line = headers_resp.get(":start_line", "")
                code = int(status_line.split()[1]) if status_line else 0

                if code == 100:
                    log_sip_event(
                        "TRYING", client=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "TRYING"
                    await self._fire_event("on_call_trying", call_id, target_addr)
                    fut = asyncio.get_running_loop().create_future()
                    self.pending_invites[call_id] = fut

                elif code in (180, 183):
                    log_sip_event("RINGING_OR_PROGRESS",
                                  client=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "RINGING"
                    await self._fire_event("on_call_ringing", call_id, target_addr)
                    fut = asyncio.get_running_loop().create_future()
                    self.pending_invites[call_id] = fut

                elif code == 486:
                    log_sip_event(
                        "BUSY", client=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "BUSY"
                    call_state["final"] = True
                    self.pending_invites.pop(call_id, None)
                    await self._fire_event("on_call_busy", call_id, target_addr)
                    return None, None

                elif 200 <= code < 300:
                    log_sip_event(
                        "CONNECTED", client=f"{target_addr}", call_id=call_id)
                    call_state["status"] = "CONNECTED"
                    call_state["final"] = True
                    await self.send_ack(headers_resp, target_addr)
                    self.active_calls[call_id] = (
                        target_addr,
                        orig_from,
                        headers_resp.get('To'),
                        headers_resp.get('Contact')
                    )
                    await self._fire_event("on_call_established", call_id, target_addr)
                    return call_id, headers_resp

                else:
                    log_sip_event(
                        "CALL_FAILED", client=f"{target_addr}", call_id=call_id, code=code)
                    call_state["status"] = "FAILED"
                    call_state["final"] = True
                    self.pending_invites.pop(call_id, None)
                    await self._fire_event("on_call_failed", call_id, target_addr, code)
                    return None, None

        except asyncio.TimeoutError:
            log_sip_event("INVITE_TIMEOUT",
                          client=f"{target_addr}", call_id=call_id)
            self.pending_invites.pop(call_id, None)
            return None, None

    async def send_ack(self, resp_headers, target_addr):
        call_id = resp_headers.get("Call-ID")
        cseq_num, _ = self.parse_cseq(resp_headers.get("CSeq"))
        to_address = resp_headers.get('To').split('<')[1].split('>')[0]

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
        log_sip_event("ACK_SENT", client=f"{target_addr}", call_id=call_id)

    async def send_bye(self, call_id):
        if call_id not in self.active_calls:
            return False
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
        log_sip_event("BYE_SENT", client=f"{addr}", call_id=call_id)
        self.active_calls.pop(call_id)
        await self._fire_event("on_call_ended", call_id)
        return True

    # ============================================================
    # OPTIONS Handler
    # ============================================================

    async def handle_options(self, headers, addr):
        log_sip_event("OPTIONS_RECEIVED", client=f"{addr}")

        if not self.check_cseq(headers, addr):
            return build_response(400, "Bad Request", headers)

        self.transport.sendto(
            build_response(
                200, "OK", headers,
                extra_headers=["Allow: REGISTER, ACK, INVITE",
                               "Accept: application/sdp"]
            ),
            addr
        )

    # ============================================================
    # Datagram Handling
    # ============================================================

    async def handle_datagram(self, data, addr):
        try:
            start_line, method, headers = parse_sip_message(data)

            # Delegate response to pending_invites
            if start_line.startswith("SIP/2.0"):
                headers[":start_line"] = start_line
                call_id = headers.get("Call-ID")
                if call_id in self.pending_invites:
                    fut = self.pending_invites.pop(call_id)
                    if not fut.done():
                        fut.set_result(headers)
                log_sip_event(
                    "GOT SIP/2.0 without pending_invites", headers=headers)
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
                log_sip_event("SIP_METHOD_NOT_IMPLEMENTED",
                              client=f"{addr}", method=method)
                resp = build_response(501, "Not Implemented", headers)
                self.transport.sendto(resp, addr)

        except Exception:
            logger.exception("Unhandled SIP server error")

    # ============================================================
    # Asyncio Datagram Endpoint
    # ============================================================

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SIPProtocol(self),
            local_addr=(self.host, self.port),
        )
        self.transport = transport
        logger.info(f"SIP server listening on {self.host}:{self.port} (UDP)")

    async def stop(self):
        if self.transport:
            self.transport.close()


class SIPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server

    def datagram_received(self, data, addr):
        asyncio.create_task(self.server.handle_datagram(data, addr))

    def error_received(self, exc):
        logger.error(f"Transport error: {exc}")
